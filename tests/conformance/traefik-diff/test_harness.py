#!/usr/bin/env python3
"""Tests of the differential harness that need no Docker: rule parsing, the request matrix,
the routing answer read from whoami's output, the comparison with the allow-list, the coverage
gate, the generated Compose project, and the corpus's diff cases against the coverage table.

    python3 -I tests/conformance/traefik-diff/test_harness.py
"""

import importlib.util
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("harness", HERE / "harness.py")
harness = importlib.util.module_from_spec(spec)
sys.modules["harness"] = harness
spec.loader.exec_module(harness)


def fixture(name):
    return json.loads((HERE / "fixtures" / name).read_text())


class Rules(unittest.TestCase):
    def test_matchers_and_negation(self):
        parsed = harness.parse_rule("Host(`a.example.com`) && (PathPrefix(`/api`) || Path(`/x`)) && !Method(`POST`)")
        self.assertEqual(
            parsed,
            [("Host", ["a.example.com"], False), ("PathPrefix", ["/api"], False), ("Path", ["/x"], False), ("Method", ["POST"], True)],
        )
        self.assertEqual(harness.parse_rule("Header(`X-A`, `1`)"), [("Header", ["X-A", "1"], False)])

    def test_normalize_matches_the_rust_table(self):
        self.assertEqual(harness.normalize("traefik.http.routers.App.tls.domains[0].main"), "traefik.http.routers.<name>.tls.domains[n].main")
        self.assertEqual(
            harness.normalize("traefik.http.middlewares.h.headers.customRequestHeaders.X-A"),
            "traefik.http.middlewares.<name>.headers.customrequestheaders.<header>",
        )
        self.assertEqual(harness.normalize("traefik.http.middlewares.p.plugin.x.y.z"), "traefik.http.middlewares.<name>.plugin.<plugin>.<option>")


class Matrix(unittest.TestCase):
    def test_requests_cover_hosts_paths_near_misses_and_methods(self):
        services = {
            "api": {
                "labels": {
                    "traefik.enable": "true",
                    "traefik.http.routers.api.rule": "Host(`example.com`) && PathPrefix(`/api`)",
                    "traefik.http.routers.api.entrypoints": "websecure",
                    "traefik.http.routers.api.tls": "true",
                }
            },
            "off": {"labels": {"traefik.http.routers.off.rule": "Host(`off.example.com`)"}},
        }
        requests = harness.matrix(services)
        seen = {(r["scheme"], r["host"], r["path"], r["method"]) for r in requests}
        for want in [
            ("https", "example.com", "/api", "GET"),
            ("https", "example.com", "/api/deeper/page?q=1", "GET"),
            ("https", "example.com", "/apix", "GET"),
            ("https", "example.com", "/", "GET"),
            ("https", "example.com", "/api", "POST"),
            ("https", "unknown.example.com", "/", "GET"),
        ]:
            self.assertIn(want, seen)
        # A container without traefik.enable is not asked about.
        self.assertFalse(any(r["host"] == "off.example.com" for r in requests))
        self.assertEqual(len(requests), len({json.dumps(r, sort_keys=True) for r in requests}))

    def test_middlewares_add_the_headers_they_react_to(self):
        services = {
            "a": {
                "labels": [
                    "traefik.enable=true",
                    "traefik.http.routers.a.rule=Host(`a.example.com`)",
                    "traefik.http.routers.a.entrypoints=web",
                    "traefik.http.middlewares.c.headers.accessControlAllowOriginList=https://app.example.com",
                    "traefik.http.middlewares.z.compress=true",
                ]
            }
        }
        requests = harness.matrix(services)
        self.assertTrue(all(r["scheme"] == "http" for r in requests))
        self.assertTrue(all(r["headers"].get("Origin") == "https://app.example.com" for r in requests))
        self.assertTrue(all("gzip" in r["headers"].get("Accept-Encoding", "") for r in requests))
        self.assertTrue(any(r["method"] == "OPTIONS" for r in requests))


class Answers(unittest.TestCase):
    def setUp(self):
        self.recorded = fixture("security-headers.json")
        request_headers, response_headers = harness.named_headers(self.recorded["services"])
        self.seen = harness.SEEN_HEADERS + request_headers
        self.response = harness.RESPONSE_HEADERS + response_headers

    def test_the_routing_answer_is_read_from_whoami(self):
        answer = harness.observe(self.recorded["traefik"], self.seen, self.response)
        self.assertEqual(answer["status"], 200)
        self.assertEqual(answer["backend"], "blog")
        self.assertEqual(answer["seen.path"], "/")
        self.assertEqual(answer["seen.header.x-forwarded-proto"], "https")
        self.assertEqual(answer["response.header.x-frame-options"], "DENY")
        self.assertEqual(answer["response.header.x-served-by"], "edge")

    def test_the_recorded_answers_agree(self):
        a = harness.observe(self.recorded["traefik"], self.seen, self.response)
        b = harness.observe(self.recorded["rdock"], self.seen, self.response)
        request = {"method": "GET"}
        self.assertEqual(harness.compare("security-headers", request, a, b, []), [])

    def test_a_difference_is_reported_unless_the_allow_list_accepts_it(self):
        a = harness.observe(self.recorded["traefik"], self.seen, self.response)
        changed = dict(self.recorded["rdock"])
        changed["headers"] = dict(changed["headers"], **{"content-encoding": "br"})
        b = harness.observe(changed, self.seen, self.response)
        request = {"method": "GET"}
        diffs = harness.compare("security-headers", request, a, b, [])
        self.assertEqual(diffs, [{"field": "response.header.content-encoding", "traefik": None, "rdock": "br", "allowed_by": None}])
        allow = [{"id": "x", "field": r"response\.header\.content-encoding", "when": {"rdock": "br"}}]
        self.assertEqual(harness.compare("security-headers", request, a, b, allow)[0]["allowed_by"], "x")
        other_case = [{"id": "x", "field": ".*", "cases": ["another-case"]}]
        self.assertIsNone(harness.compare("security-headers", request, a, b, other_case)[0]["allowed_by"])

    def test_the_summary_fails_on_open_differences_and_errors(self):
        results = [
            {"case": "a", "errors": [], "requests": [{"request": {"method": "GET", "scheme": "http", "host": "h", "path": "/"}, "differences": []}]},
            {"case": "b", "errors": ["boom"], "requests": []},
        ]
        text, failed = harness.summarize(results)
        self.assertTrue(failed)
        self.assertIn("FAIL b: boom", text)
        text, failed = harness.summarize(results[:1])
        self.assertFalse(failed)
        self.assertIn("1 agree", text)


class Gate(unittest.TestCase):
    def setUp(self):
        self.coverage = harness.load_coverage()
        self.allowlist = json.loads(harness.ALLOWLIST.read_text())["differences"]

    def test_only_exact_or_allow_listed_options_pass(self):
        ok = {"traefik.http.routers.a.rule": "Host(`a`)", "traefik.http.middlewares.c.compress": "true"}
        self.assertEqual(harness.coverage_gate(ok, self.coverage, self.allowlist), [])
        bad = {"traefik.http.middlewares.d.digestauth.users": "x", "traefik.http.routers.a.colour": "blue"}
        errors = harness.coverage_gate(bad, self.coverage, self.allowlist)
        self.assertEqual(len(errors), 2)
        unlisted = {"traefik.http.services.s.loadbalancer.strategy": "wrr"}
        self.assertIn("without an allow-list entry", harness.coverage_gate(unlisted, self.coverage, [])[0])

    def test_every_allow_list_entry_has_a_reason_a_source_and_a_known_option(self):
        ids = set()
        for entry in self.allowlist:
            self.assertTrue(entry["reason"] and entry["source"], entry["id"])
            self.assertNotIn(entry["id"], ids)
            ids.add(entry["id"])
            if "option" in entry:
                self.assertIn(entry["option"], self.coverage, entry["id"])
                self.assertEqual(self.coverage[entry["option"]]["status"], "approximate", entry["id"])

    def test_the_corpus_diff_cases_pass_the_gate(self):
        cases = harness.diff_cases()
        self.assertGreaterEqual(len(cases), 10)
        for case in cases:
            text = (harness.CORPUS / case / "compose.yaml").read_text()
            labels = {}
            for line in text.splitlines():
                line = line.strip().lstrip("- ").strip('"')
                if line.startswith("traefik.") and ("=" in line or ":" in line):
                    sep = "=" if "=" in line and (":" not in line or line.index("=") < line.index(":")) else ":"
                    key, value = line.split(sep, 1)
                    labels[key.strip()] = value.strip()
            self.assertEqual(harness.coverage_gate(labels, self.coverage, self.allowlist), [], case)


class Project(unittest.TestCase):
    def test_the_project_pins_images_and_mounts_the_same_certificate(self):
        compose = {"services": {
            "traefik": {"image": "traefik:v3.7.19"},
            "app": {"image": "example/app", "labels": {"traefik.enable": "true", "traefik.http.services.app.loadbalancer.server.port": "8080"}},
            "db": {"image": "postgres"},
        }}
        project = harness.project("case", compose, "rdock:ci", "/work", 999)
        services = project["services"]
        self.assertEqual(sorted(services), ["app", "rdock", "traefik"])
        self.assertIn("@sha256:", services["traefik"]["image"])
        self.assertIn("@sha256:", services["app"]["image"])
        self.assertEqual(services["app"]["command"], ["--port", "8080"])
        self.assertEqual(services["rdock"]["group_add"], ["999"])
        self.assertIn("/work/certs:/certs:ro", services["rdock"]["volumes"])
        self.assertIn("/work/certs:/certs:ro", services["traefik"]["volumes"])

    def test_the_proxy_image_is_told_from_the_backend_image(self):
        for image in ["traefik", "traefik:v3.7.19", "docker.io/library/traefik:v3.7", "traefik@sha256:aa94"]:
            self.assertTrue(harness.is_traefik_image(image), image)
        for image in ["traefik/whoami:v1.12.0", "traefik/whoami@sha256:c471", "nginx:1.30", None, ""]:
            self.assertFalse(harness.is_traefik_image(image), image)

    def test_every_diff_case_has_a_request_to_send(self):
        # The backends are `traefik/whoami`: a filter on the word "traefik" once dropped them all.
        for case in harness.diff_cases():
            text = (harness.CORPUS / case / json.loads((harness.CORPUS / case / "case.json").read_text())["input"]).read_text()
            self.assertIn("traefik/whoami", text, case)


if __name__ == "__main__":
    unittest.main()
