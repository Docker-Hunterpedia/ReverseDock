#!/usr/bin/env python3
"""Judge a Gateway API conformance report (ADR-0029) and print a summary.

    check-report.py --report out/report.yaml [--options options.yaml] [--allow-partial]

Prints a table per profile (core and extended result, counts, skipped and failed test names) to
stdout and, as Markdown, to $GITHUB_STEP_SUMMARY (or --summary). Exit status 0 when the report
is acceptable, 1 when it is not, 2 when the report cannot be read.

Errors (always fail):
  * the report is missing, unreadable, or for another Gateway API version or channel;
  * a skipTests entry of options.yaml has no reason and issue link in the comment above it;
  * a stale skip: a skipTests entry that is not in any profile's skippedTests of the report
    (the test passes, does not apply, or the name is misspelled). Remove it.

Run results (fail, but only warn with --allow-partial, which is for the informational CI jobs):
  * a profile of options.yaml is missing from the report;
  * a profile's core or extended result is `failure`;
  * a profile's core ran no test at all (nothing is proven);
  * a `partial` result with more than 5 skipped tests, which upstream refuses at v1.7
    (conformance/apis/v1/profilereport.go, Status.IsConformant).

Uses PyYAML when it is installed (CI installs it); otherwise a small parser that reads the
block-style YAML the suite writes and options.yaml.
"""

import argparse
import os
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only where PyYAML is absent
    yaml = None

MAX_PARTIAL_SKIPS = 5  # upstream v1.7 limit for a `partial` result


# --- a minimal YAML reader (fallback) ---------------------------------------------------------

def _scalar(text):
    text = text.strip()
    if text == "":
        return None
    if text[0] in "'\"" and text[-1] == text[0] and len(text) >= 2:
        return text[1:-1]
    if text == "[]":
        return []
    if text == "{}":
        return {}
    if text[0] == "[" and text[-1] == "]":
        return [_scalar(p) for p in text[1:-1].split(",") if p.strip()]
    if text[0] == "{" and text[-1] == "}":
        out = {}
        for pair in text[1:-1].split(","):
            if pair.strip():
                key, _, value = pair.partition(":")
                out[key.strip()] = _scalar(value)
        return out
    if text in ("null", "~"):
        return None
    if text in ("true", "false"):
        return text == "true"
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text


def _mini_lines(text):
    lines = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#") or raw.strip() in ("---", "..."):
            continue
        body = raw.rstrip()
        value_part = body.split(":", 1)[-1].strip() if ":" in body else body.strip()
        if not value_part.startswith(("'", '"')):
            body = re.sub(r"\s+#.*$", "", body)
        lines.append((len(body) - len(body.lstrip(" ")), body.strip()))
    return lines


def _mini_block(lines, i, indent):
    if lines[i][1].startswith("- ") or lines[i][1] == "-":
        return _mini_list(lines, i, indent)
    return _mini_map(lines, i, indent)


def _mini_list(lines, i, indent):
    out = []
    while i < len(lines) and lines[i][0] == indent and (lines[i][1].startswith("- ") or lines[i][1] == "-"):
        content = lines[i][1][1:].strip()
        if re.match(r"^[^'\"\[{][^:]*:(\s|$)", content):  # "- key: value" starts a mapping
            lines[i] = (indent + 2, content)
            value, i = _mini_map(lines, i, indent + 2)
            out.append(value)
        else:
            out.append(_scalar(content))
            i += 1
    return out, i


def _mini_map(lines, i, indent):
    out = {}
    while i < len(lines) and lines[i][0] == indent and not lines[i][1].startswith("- "):
        key, _, rest = lines[i][1].partition(":")
        key = key.strip().strip("'\"")
        rest = rest.strip()
        i += 1
        if rest:
            out[key] = _scalar(rest)
        elif i < len(lines) and (
            lines[i][0] > indent or (lines[i][0] == indent and lines[i][1].startswith("- "))
        ):
            out[key], i = _mini_block(lines, i, lines[i][0])
        else:
            out[key] = None
    return out, i


def load_yaml(text):
    if yaml is not None:
        return yaml.safe_load(text)
    lines = _mini_lines(text)
    if not lines:
        return None
    value, _ = _mini_block(lines, 0, lines[0][0])
    return value


# --- options.yaml: skips ----------------------------------------------------------------------

ISSUE_LINK = re.compile(r"https?://\S+/issues/\d+|(?<![\w/])#\d+")


def skip_entries(options_text):
    """Return [(name, comment_text)] for the entries of the uncommented `skipTests:` list."""
    lines = options_text.splitlines()
    entries = []
    in_list = False
    for n, line in enumerate(lines):
        if re.match(r"^skipTests:\s*(\[\s*\])?\s*(#.*)?$", line):
            in_list = not re.search(r"\[\s*\]", line)
            continue
        if not in_list:
            continue
        match = re.match(r"^\s*-\s+([^\s#]+)\s*(#.*)?$", line)
        if match:
            comment = [match.group(2) or ""]
            k = n - 1
            while k >= 0 and lines[k].lstrip().startswith("#"):
                comment.append(lines[k])
                k -= 1
            entries.append((match.group(1), "\n".join(comment)))
        elif line.strip() and not line.lstrip().startswith("#"):
            in_list = False  # the next top-level key ends the list
    return entries


def skip_lint(entries):
    problems = []
    for name, comment in entries:
        text = re.sub(r"[#\s]+", " ", comment)
        without_link = ISSUE_LINK.sub("", text).strip()
        if not ISSUE_LINK.search(comment) or len(without_link) < 12:
            problems.append(
                f"skipTests entry {name} needs a reason and an issue link in the comment above it "
                "(see the rule in options.yaml)"
            )
    return problems


# --- the report -------------------------------------------------------------------------------

def stat(status, name):
    stats = (status or {}).get("statistics") or {}
    for key, value in stats.items():
        if str(key).lower() == name:
            return int(value or 0)
    return 0


def levels(profile):
    """Yield (level, status) for core and, when present, extended."""
    yield "core", profile.get("core") or {}
    if profile.get("extended"):
        yield "extended", profile["extended"]


def analyse(report, options, options_text, expected_version, allow_partial):
    """Return (errors, warnings). `allow_partial` turns run results into warnings."""
    errors, warnings = [], []
    run_problems = warnings if allow_partial else errors

    version = str(report.get("gatewayAPIVersion", ""))
    channel = str(report.get("gatewayAPIChannel", ""))
    if version != expected_version:
        errors.append(f"report is for Gateway API {version or '(none)'}, expected {expected_version}")
    if channel != "standard":
        errors.append(f"report is for the {channel or '(none)'} channel, expected standard")

    profiles = {p.get("name"): p for p in report.get("profiles") or []}
    for wanted in (options or {}).get("conformanceProfiles") or []:
        if wanted not in profiles:
            run_problems.append(f"profile {wanted} is in options.yaml but not in the report")

    skipped_in_report = set()
    for name, profile in profiles.items():
        for level, status in levels(profile):
            result = status.get("result")
            skipped = stat(status, "skipped")
            skipped_in_report.update(status.get("skippedTests") or [])
            if result == "failure":
                failed = ", ".join(status.get("failedTests") or []) or "no test names reported"
                run_problems.append(f"{name} {level}: failure ({stat(status, 'failed')} failed: {failed})")
            if result == "partial" and skipped > MAX_PARTIAL_SKIPS:
                run_problems.append(
                    f"{name} {level}: partial with {skipped} skipped tests; upstream refuses more than "
                    f"{MAX_PARTIAL_SKIPS} at v1.7"
                )
            if level == "core" and stat(status, "passed") + stat(status, "failed") + skipped == 0:
                run_problems.append(f"{name} core: no test ran, so nothing is proven for this profile")

    entries = skip_entries(options_text or "")
    errors.extend(skip_lint(entries))
    for entry, _ in entries:
        if entry not in skipped_in_report:
            errors.append(f"stale skip: {entry} is in skipTests but not in any skippedTests of the report; remove it")
    return errors, warnings


def render(report, errors, warnings, markdown):
    impl = report.get("implementation") or {}
    head = (
        f"{impl.get('project', '?')} {impl.get('version', '?')} against Gateway API "
        f"{report.get('gatewayAPIVersion', '?')} ({report.get('gatewayAPIChannel', '?')}), "
        f"mode {report.get('mode', '?')}"
    )
    rows = []
    notes = []
    for profile in report.get("profiles") or []:
        for level, status in levels(profile):
            rows.append(
                (
                    profile.get("name", "?"),
                    level,
                    str(status.get("result", "?")),
                    str(stat(status, "passed")),
                    str(stat(status, "skipped")),
                    str(stat(status, "failed")),
                )
            )
            for kind, key in (("skipped", "skippedTests"), ("failed", "failedTests")):
                names = status.get(key) or []
                if names:
                    notes.append((profile.get("name", "?"), level, kind, names))
    columns = ("profile", "level", "result", "passed", "skipped", "failed")
    out = []
    if markdown:
        out.append("## Gateway API conformance")
        out.append("")
        out.append(head)
        out.append("")
        out.append("| " + " | ".join(columns) + " |")
        out.append("|" + "|".join("---" for _ in columns) + "|")
        out.extend("| " + " | ".join(row) + " |" for row in rows)
        for profile_name, level, kind, names in notes:
            out.append("")
            out.append(f"**{profile_name} {level}, {kind} ({len(names)}):** " + ", ".join(f"`{n}`" for n in names))
    else:
        widths = [max(len(c), *(len(r[i]) for r in rows)) if rows else len(c) for i, c in enumerate(columns)]
        out.append(head)
        out.append("  ".join(c.ljust(widths[i]) for i, c in enumerate(columns)).rstrip())
        out.extend("  ".join(v.ljust(widths[i]) for i, v in enumerate(row)).rstrip() for row in rows)
        for profile_name, level, kind, names in notes:
            out.append(f"{profile_name} {level} {kind} ({len(names)}): " + ", ".join(names))
    out.append("")
    for message in errors:
        out.append(f"- **error:** {message}" if markdown else f"error: {message}")
    for message in warnings:
        out.append(f"- warning: {message}" if markdown else f"warning: {message}")
    verdict = "FAILED" if errors else ("passed with warnings" if warnings else "passed")
    out.append("")
    out.append(
        f"Result of this check: **{verdict}**. A CI run is not a conformance claim; see the README."
        if markdown
        else f"result: {verdict}"
    )
    return "\n".join(out) + "\n"


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--report", required=True, help="the report YAML written by the suite")
    parser.add_argument("--options", default=os.path.join(here, "options.yaml"))
    parser.add_argument("--gateway-api-version", default="v1.7.0")
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="report failures, missing profiles and too many skips as warnings (informational CI jobs)",
    )
    parser.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY"), help="Markdown output file")
    args = parser.parse_args(argv)

    try:
        with open(args.report, encoding="utf-8") as handle:
            report = load_yaml(handle.read())
        with open(args.options, encoding="utf-8") as handle:
            options_text = handle.read()
        options = load_yaml(options_text) or {}
    except Exception as exc:  # noqa: BLE001 - any read or parse error is exit 2
        print(f"error: cannot read the report or options: {exc}", file=sys.stderr)
        return 2
    if not isinstance(report, dict) or "profiles" not in report:
        print(f"error: {args.report} is not a conformance report (no `profiles`)", file=sys.stderr)
        return 2

    errors, warnings = analyse(report, options, options_text, args.gateway_api_version, args.allow_partial)
    sys.stdout.write(render(report, errors, warnings, markdown=False))
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(render(report, errors, warnings, markdown=True))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
