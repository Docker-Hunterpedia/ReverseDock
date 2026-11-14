#!/usr/bin/env python3
"""Differential test of Traefik labels (ADR-0033, layer 3 of "conformance-tested").

For each corpus case marked `"diff": true` in tests/conformance/traefik-compose/<case>/case.json,
the harness starts the case's labelled services as whoami backends next to a pinned Traefik
v3.7 and the rdock image under test (both reading the same Docker labels), sends the same
request matrix to both, and compares the routing answer: status, which backend answered, the
request the backend saw (path and selected headers), redirects (status and Location) and
selected response headers. Differences listed in allowlist.json (each with a reason and a
source) are accepted; anything else fails.

Pass rule: total agreement on every request, apart from the allow-list. A case may only use
labels the coverage table (tests/conformance/traefik-labels/coverage.json) marks exact, or
approximate with an allow-list entry naming the option; the gate refuses anything else.

Standard library only; run with `python3 -I`. `run` needs Docker with Compose v2 and openssl;
everything else (rule parsing, the request matrix, the comparison, the coverage gate) is
tested without Docker by test_harness.py.

    python3 -I tests/conformance/traefik-diff/harness.py run --rdock-image rdock:ci [--case NAME] [--out DIR]
    python3 -I tests/conformance/traefik-diff/harness.py matrix --compose-json FILE   # print the matrix
"""

import argparse
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
CORPUS = ROOT / "tests" / "conformance" / "traefik-compose"
COVERAGE = ROOT / "tests" / "conformance" / "traefik-labels" / "coverage.json"
ALLOWLIST = HERE / "allowlist.json"

# Pinned by digest. Source: Docker Hub's tag API
# (https://hub.docker.com/v2/repositories/library/traefik/tags/v3.7.19 and
# https://hub.docker.com/v2/repositories/traefik/whoami/tags/v1.12.0), read 2026-11-14; the
# digests are the multi-architecture index digests.
TRAEFIK_IMAGE = "traefik:v3.7.19@sha256:aa942a00bce033c909bf1f7e861d93761be4b31a035f10d2410d33e38a8f41cf"
WHOAMI_IMAGE = "traefik/whoami:v1.12.0@sha256:c4717a8d1f0134a7444e24f881160e033991f23027c6c5a9a3f8fd22e70d1d44"

# Host ports of the two proxies: (http, https).
PORTS = {"traefik": (18080, 18443), "rdock": (28080, 28443)}

# Response headers compared on every request, besides the custom ones the labels name.
RESPONSE_HEADERS = [
    "location",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "content-security-policy",
    "content-security-policy-report-only",
    "permissions-policy",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-max-age",
    "content-encoding",
    "www-authenticate",
]

# Request headers the backend saw, compared on every request, besides the custom ones.
SEEN_HEADERS = ["host", "x-forwarded-proto", "x-forwarded-prefix", "x-forwarded-host", "authorization"]

MATCHER = re.compile(r"(!?)\s*([A-Za-z]+)\(\s*((?:`[^`]*`\s*,?\s*)*)\)")
ARGUMENT = re.compile(r"`([^`]*)`")


# --- Coverage ------------------------------------------------------------------------------


def normalize(key):
    """A label key in the coverage table's form (the Rust `coverage::normalize`)."""
    parts = key.lower().split(".")
    if len(parts) > 3 and parts[1] in ("http", "tcp", "udp") and parts[2] in ("routers", "services", "middlewares"):
        parts[3] = "<name>"
        if parts[2] == "middlewares" and len(parts) > 5 and parts[4] == "plugin":
            parts = parts[:5] + ["<plugin>", "<option>"]
    if len(parts) > 3 and parts[1] == "tls" and parts[2] == "stores":
        parts[3] = "<store>"
    n = len(parts)
    if (n >= 2 and parts[n - 2] in ("customrequestheaders", "customresponseheaders", "sslproxyheaders")) or (
        n >= 3 and parts[n - 2] == "headers" and parts[n - 3] == "healthcheck"
    ):
        parts[n - 1] = "<header>"
    if n >= 2 and parts[n - 2] == "statusrewrites":
        parts[n - 1] = "<status>"
    return re.sub(r"\[\d+\]", "[n]", ".".join(parts))


def load_coverage(path=COVERAGE):
    table = json.loads(Path(path).read_text())
    return {row["key"]: row for row in table["options"]}


def coverage_gate(labels, coverage, allowlist):
    """Errors for labels a differential case must not use: any label that is not translated,
    and approximate ones without an allow-list entry naming the option."""
    errors = []
    allowed_options = {entry.get("option") for entry in allowlist}
    for key in sorted(labels):
        if not key.lower().startswith("traefik."):
            continue
        row = coverage.get(normalize(key))
        if row is None:
            errors.append(f"{key}: not in the coverage table")
        elif row["status"] in ("manual", "none"):
            errors.append(f"{key}: marked {row['status']}; a differential case uses exact options only")
        elif row["status"] == "approximate" and row["key"] not in allowed_options:
            errors.append(f"{key}: approximate ({row['note']}) without an allow-list entry for {row['key']}")
    return errors


# --- Labels and rules ----------------------------------------------------------------------


def is_traefik_image(image):
    """Whether a Compose image is the Traefik proxy itself: the repository's last component is
    `traefik` (`traefik:v3.7`, `docker.io/library/traefik@sha256:…`). `traefik/whoami`, the
    backend of the corpus, is not."""
    name = str(image or "").split("@", 1)[0]
    last = name.rsplit("/", 1)[-1]
    return last.split(":", 1)[0] == "traefik"


def labels_of(service):
    """A Compose service's labels (from `docker compose config --format json`) as a dict."""
    raw = service.get("labels") or {}
    if isinstance(raw, list):
        return dict(item.split("=", 1) if "=" in item else (item, "") for item in raw)
    return {k: "" if v is None else str(v) for k, v in raw.items()}


def parse_rule(rule):
    """Every matcher of a Traefik v3 rule as (name, [arguments], negated); logic is ignored:
    the matrix tries each value and a near miss, so both proxies are asked the same questions."""
    return [(m.group(2), ARGUMENT.findall(m.group(3)), m.group(1) == "!") for m in MATCHER.finditer(rule)]


def routers(services):
    """HTTP routers of all services: name, rule, entry points, TLS, middlewares and labels."""
    out = []
    for service_name, service in sorted(services.items()):
        labels = {k.lower(): v for k, v in labels_of(service).items()}
        if labels.get("traefik.enable") != "true":
            continue
        names = sorted({k.split(".")[3] for k in labels if k.startswith("traefik.http.routers.") and len(k.split(".")) > 4})
        for name in names:
            prefix = f"traefik.http.routers.{name}."
            out.append(
                {
                    "service": service_name,
                    "name": name,
                    "rule": labels.get(prefix + "rule", ""),
                    "entrypoints": [e.strip() for e in labels.get(prefix + "entrypoints", "").split(",") if e.strip()],
                    "tls": any(k.startswith(prefix + "tls") and labels[k] != "false" for k in labels),
                    "middlewares": [m.strip() for m in labels.get(prefix + "middlewares", "").split(",") if m.strip()],
                }
            )
    return out


def named_headers(services):
    """Custom request and response header names the labels set, to compare them too."""
    request, response = set(), set()
    for service in services.values():
        for key in labels_of(service):
            lower = key.lower()
            if ".customrequestheaders." in lower:
                request.add(lower.rsplit(".", 1)[1])
            if ".customresponseheaders." in lower:
                response.add(lower.rsplit(".", 1)[1])
    return sorted(request), sorted(response)


def middleware_kinds(services):
    """The Traefik middleware types the labels declare (`headers`, `compress`, …)."""
    kinds = set()
    for service in services.values():
        for key in labels_of(service):
            parts = key.lower().split(".")
            if len(parts) > 4 and parts[:3] == ["traefik", "http", "middlewares"]:
                kinds.add(parts[4])
                if parts[4] == "headers" and len(parts) > 5 and parts[5].startswith("accesscontrol"):
                    kinds.add("cors")
                if parts[4] == "ratelimit" and "requestheadername" in key.lower():
                    kinds.add("ratelimit-header")
    return kinds


def matrix(services):
    """The requests sent to both proxies: for every router, each host and path of its rule, a
    deeper path, a sibling path (a near miss for prefixes), the root, another method, and an
    unknown host; extra headers where middlewares react to them."""
    kinds = middleware_kinds(services)
    base_headers = {"User-Agent": "rdock-traefik-diff"}
    if "compress" in kinds:
        base_headers["Accept-Encoding"] = "gzip, br"
    if "cors" in kinds:
        base_headers["Origin"] = "https://app.example.com"
    if "ratelimit-header" in kinds:
        base_headers["X-Api-Key"] = "diff"
    requests = []

    def add(scheme, host, path, method="GET", extra=None):
        headers = dict(base_headers)
        headers.update(extra or {})
        request = {"scheme": scheme, "host": host, "path": path, "method": method, "headers": headers}
        if request not in requests:
            requests.append(request)

    for router in routers(services):
        matchers = parse_rule(router["rule"])
        hosts = [a for (m, args, neg) in matchers if m == "Host" and not neg for a in args] or ["unmatched.example.com"]
        paths = [a for (m, args, neg) in matchers if m in ("Path", "PathPrefix") and not neg for a in args] or ["/"]
        methods = [a for (m, args, neg) in matchers if m == "Method" for a in args]
        headers = [tuple(args[:2]) for (m, args, neg) in matchers if m == "Header" and len(args) >= 2]
        schemes = []
        for entrypoint in router["entrypoints"] or ["web", "websecure"]:
            schemes.append("https" if entrypoint == "websecure" else "http")
        for scheme in dict.fromkeys(schemes):
            for host in hosts:
                for path in paths:
                    extra = dict(headers)
                    add(scheme, host, path, methods[0] if methods else "GET", extra)
                    add(scheme, host, path.rstrip("/") + "/deeper/page?q=1", "GET", extra)
                    if path != "/":
                        add(scheme, host, path.rstrip("/") + "x", "GET", extra)
                        add(scheme, host, "/", "GET", extra)
                    add(scheme, host, path, "POST", extra)
                if "cors" in kinds:
                    add(scheme, host, paths[0], "OPTIONS", {"Access-Control-Request-Method": "PUT"})
            add(scheme, "unknown.example.com", "/", "GET")
    return requests


# --- Sending and observing -----------------------------------------------------------------


def send(proxy, request, timeout=10.0):
    """One request to a proxy on this host; SNI and Host carry the request's host."""
    http_port, https_port = PORTS[proxy]
    port = https_port if request["scheme"] == "https" else http_port
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    if request["scheme"] == "https":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=request["host"])
    connection = http.client.HTTPConnection(request["host"], port, timeout=timeout)
    connection.sock = sock
    headers = dict(request["headers"])
    headers["Host"] = request["host"]
    connection.request(request["method"], request["path"], headers=headers)
    response = connection.getresponse()
    body = response.read(65536).decode("utf-8", "replace")
    out = {"status": response.status, "headers": {k.lower(): v for k, v in response.getheaders()}, "body": body}
    connection.close()
    return out


def observe(response, seen_headers, response_headers):
    """The routing answer of one response: status, the backend that answered (whoami's
    `Hostname:`), the request line and headers it saw, and the selected response headers."""
    answer = {"status": response["status"]}
    lines = response["body"].splitlines()
    backend = next((l.split(":", 1)[1].strip() for l in lines if l.startswith("Hostname:")), None)
    answer["backend"] = backend
    if backend is not None:
        request_line = next((l for l in lines if re.match(r"^[A-Z]+ \S+ HTTP/", l)), "")
        answer["seen.path"] = request_line.split(" ")[1] if request_line else None
        seen = {}
        for line in lines:
            if ":" in line and not line.startswith(("Hostname:", "IP:", "RemoteAddr:")):
                name, value = line.split(":", 1)
                seen.setdefault(name.strip().lower(), value.strip())
        for name in seen_headers:
            value = seen.get(name)
            answer[f"seen.header.{name}"] = "<present>" if name == "authorization" and value else value
    for name in response_headers:
        answer[f"response.header.{name}"] = response["headers"].get(name)
    return answer


def compare(case, request, traefik, rdock, allowlist):
    """The fields where the two answers differ, each with the allow-list entry that accepts it
    (or None)."""
    differences = []
    for field in sorted(set(traefik) | set(rdock)):
        a, b = traefik.get(field), rdock.get(field)
        if a == b:
            continue
        entry = allowed(case, request, field, a, b, allowlist)
        differences.append({"field": field, "traefik": a, "rdock": b, "allowed_by": entry["id"] if entry else None})
    return differences


def value_matches(expected, actual):
    """`*` is any value, `re:<pattern>` a regular expression over the whole value, anything
    else the exact value."""
    expected = str(expected)
    if expected == "*":
        return True
    if expected.startswith("re:"):
        return re.fullmatch(expected[3:], str(actual)) is not None
    return expected == str(actual)


def allowed(case, request, field, traefik, rdock, allowlist):
    for entry in allowlist:
        if entry.get("cases", ["*"]) != ["*"] and case not in entry["cases"]:
            continue
        if not re.fullmatch(entry["field"], field):
            continue
        method = entry.get("method")
        if method and request["method"] != method:
            continue
        when = entry.get("when", {})
        if "traefik" in when and not value_matches(when["traefik"], traefik):
            continue
        if "rdock" in when and not value_matches(when["rdock"], rdock):
            continue
        return entry
    return None


# --- The Docker project ---------------------------------------------------------------------


def project(case, compose, rdock_image, workdir, socket_gid):
    """A Compose project (JSON, which Compose reads as YAML): the case's labelled services as
    whoami backends, a pinned Traefik and the rdock image, on one network."""
    services = {}
    for name, service in compose.get("services", {}).items():
        if "traefik" in str(service.get("image", "")).split("/")[-1].split(":")[0]:
            continue  # the case's own Traefik: the harness brings its own
        labels = labels_of(service)
        if not any(k.lower().startswith("traefik.") for k in labels):
            continue
        port = next((v for k, v in labels.items() if k.lower().endswith("loadbalancer.server.port")), "80")
        services[name] = {
            "image": WHOAMI_IMAGE,
            "hostname": name,
            "command": ["--port", str(port)],
            "expose": [str(port)],
            "labels": labels,
            "networks": ["diff"],
        }
    socket_mount = "/var/run/docker.sock:/var/run/docker.sock:ro"
    services["traefik"] = {
        "image": TRAEFIK_IMAGE,
        "command": [
            "--entrypoints.web.address=:80",
            "--entrypoints.websecure.address=:443",
            "--providers.docker=true",
            "--providers.docker.exposedbydefault=false",
            f"--providers.docker.network={case}_diff",
            "--providers.file.filename=/etc/traefik/dynamic.yml",
            "--log.level=ERROR",
        ],
        "ports": [f"127.0.0.1:{PORTS['traefik'][0]}:80", f"127.0.0.1:{PORTS['traefik'][1]}:443"],
        "volumes": [socket_mount, f"{workdir}/traefik-dynamic.yml:/etc/traefik/dynamic.yml:ro", f"{workdir}/certs:/certs:ro"],
        "networks": ["diff"],
    }
    services["rdock"] = {
        "image": rdock_image,
        "command": ["run", "--config", "/etc/rdock/rdock.yaml"],
        "group_add": [str(socket_gid)],
        "ports": [f"127.0.0.1:{PORTS['rdock'][0]}:80", f"127.0.0.1:{PORTS['rdock'][1]}:443"],
        "volumes": [socket_mount, f"{workdir}/rdock.yaml:/etc/rdock/rdock.yaml:ro", f"{workdir}/certs:/certs:ro"],
        "networks": ["diff"],
    }
    return {"name": case, "services": services, "networks": {"diff": {}}}


# The static side of the comparison: both proxies get the same entry points and certificate and
# no automatic HTTPS, so only label semantics are compared. rdock's HTTPS redirect is off here
# because Traefik has none unless configured (the defaults that differ are on the website's
# migration page, not in this test).
RDOCK_CONFIG = """# The differential test's rdock configuration (tests/conformance/traefik-diff/harness.py).
listeners:
  web: { address: ":80" }
  websecure: { address: ":443", tls: {} }
acme: false
defaults:
  redirect_http_to_https: false
  certificate: default
certificates:
  default: { cert_file: /certs/default.pem, key_file: /certs/default.key }
providers:
  docker: { network: %(network)s }
"""

TRAEFIK_DYNAMIC = """tls:
  stores:
    default:
      defaultCertificate:
        certFile: /certs/default.pem
        keyFile: /certs/default.key
"""


def docker(*args, check=True, capture=False):
    return subprocess.run(["docker", *args], check=check, text=True, capture_output=capture)


def wait_ready(requests, deadline_seconds=90):
    """Until both proxies answer the first request of the matrix with something other than a
    404 (the providers have seen the containers), or the deadline passes."""
    deadline = time.monotonic() + deadline_seconds
    probe = requests[0]
    while time.monotonic() < deadline:
        try:
            if all(send(p, probe, timeout=3)["status"] != 404 for p in PORTS):
                time.sleep(2)  # let both settle on the full set of containers
                return True
        except OSError:
            pass
        time.sleep(1)
    return False


def run_case(case, rdock_image, out, allowlist, coverage):
    directory = CORPUS / case
    meta = json.loads((directory / "case.json").read_text())
    command = ["compose", "-f", str(directory / meta["input"])]
    if meta.get("args", {}).get("env_file"):
        command += ["--env-file", str(directory / meta["args"]["env_file"])]
    compose = json.loads(docker(*command, "config", "--format", "json", capture=True).stdout)
    services = {n: s for n, s in compose.get("services", {}).items() if not is_traefik_image(s.get("image"))}
    labels = {k: v for s in services.values() for k, v in labels_of(s).items()}
    gate = coverage_gate(labels, coverage, allowlist)
    if gate:
        return {"case": case, "errors": gate, "requests": []}
    workdir = out / case
    (workdir / "certs").mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
         "-subj", "/CN=example.com", "-addext", "subjectAltName=DNS:example.com,DNS:*.example.com",
         "-keyout", str(workdir / "certs" / "default.key"), "-out", str(workdir / "certs" / "default.pem")],
        check=True, capture_output=True,
    )
    os.chmod(workdir / "certs" / "default.key", 0o644)
    (workdir / "rdock.yaml").write_text(RDOCK_CONFIG % {"network": f"{case}_diff"})
    (workdir / "traefik-dynamic.yml").write_text(TRAEFIK_DYNAMIC)
    gid = os.stat("/var/run/docker.sock").st_gid
    (workdir / "project.json").write_text(json.dumps(project(case, compose, rdock_image, workdir, gid), indent=2))
    requests = matrix(services)
    if not requests:
        return {"case": case, "errors": ["the case has no router to send a request to"], "requests": []}
    request_headers, response_headers = named_headers(services)
    results = {"case": case, "errors": [], "requests": []}
    try:
        docker("compose", "-f", str(workdir / "project.json"), "up", "-d", "--wait")
        if not wait_ready(requests):
            results["errors"].append("the proxies did not route the case's containers within 90s")
            return results
        for request in requests:
            answers = {}
            for proxy in PORTS:
                try:
                    response = send(proxy, request)
                    answers[proxy] = observe(response, SEEN_HEADERS + request_headers, RESPONSE_HEADERS + response_headers)
                except OSError as err:
                    answers[proxy] = {"status": f"error: {err.__class__.__name__}"}
            results["requests"].append(
                {"request": request, "answers": answers, "differences": compare(case, request, answers["traefik"], answers["rdock"], allowlist)}
            )
    finally:
        logs = docker("compose", "-f", str(workdir / "project.json"), "logs", "--no-color", check=False, capture=True)
        (workdir / "logs.txt").write_text((logs.stdout or "") + (logs.stderr or ""))
        docker("compose", "-f", str(workdir / "project.json"), "down", "-v", "--remove-orphans", check=False)
    return results


def diff_cases():
    return sorted(d.name for d in CORPUS.iterdir() if d.is_dir() and json.loads((d / "case.json").read_text()).get("diff"))


def summarize(results):
    """(text, failed): every unaccepted difference and error, then the counts."""
    lines, failed = [], False
    total = agreed = accepted = 0
    for case in results:
        for error in case["errors"]:
            lines.append(f"FAIL {case['case']}: {error}")
            failed = True
        for entry in case["requests"]:
            total += 1
            open_diffs = [d for d in entry["differences"] if d["allowed_by"] is None]
            if not entry["differences"]:
                agreed += 1
            elif not open_diffs:
                accepted += 1
            for d in open_diffs:
                r = entry["request"]
                lines.append(
                    f"FAIL {case['case']}: {r['method']} {r['scheme']}://{r['host']}{r['path']}: {d['field']}: traefik={d['traefik']!r} rdock={d['rdock']!r}"
                )
                failed = True
    lines.append(f"{len(results)} case(s), {total} request(s): {agreed} agree, {accepted} differ only as the allow-list accepts, {total - agreed - accepted} differ")
    return "\n".join(lines), failed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="start Traefik and rdock per case and compare (needs Docker)")
    run.add_argument("--rdock-image", required=True)
    run.add_argument("--case", action="append", help="only these corpus cases (default: every case with diff: true)")
    run.add_argument("--out", default="traefik-diff-out", help="working directory and report")
    show = sub.add_parser("matrix", help="print the request matrix of a `docker compose config --format json` file")
    show.add_argument("--compose-json", required=True)
    args = parser.parse_args(argv)
    if args.command == "matrix":
        compose = json.loads(Path(args.compose_json).read_text())
        print(json.dumps(matrix(compose.get("services", {})), indent=2))
        return 0
    allowlist = json.loads(ALLOWLIST.read_text())["differences"]
    coverage = load_coverage()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    results = [run_case(case, args.rdock_image, out, allowlist, coverage) for case in (args.case or diff_cases())]
    (out / "report.json").write_text(json.dumps(results, indent=2))
    text, failed = summarize(results)
    (out / "summary.txt").write_text(text + "\n")
    print(text)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
