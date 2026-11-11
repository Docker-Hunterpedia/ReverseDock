#!/usr/bin/env python3
"""Offline tests of check-report.py: python3 -I tests/conformance/gateway-api/test_check_report.py

Reports below have the shape the suite writes (conformance/apis/v1, marshalled by sigs.k8s.io/yaml).
Every case runs twice: with PyYAML and with the built-in fallback parser.
"""

import importlib.util
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("check_report", os.path.join(HERE, "check-report.py"))
cr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cr)

OPTIONS = """\
gatewayClassName: reversedock
conformanceProfiles:
  - GATEWAY-HTTP
  - GATEWAY-GRPC
skipTests: []
"""

OPTIONS_WITH_SKIP = """\
conformanceProfiles:
  - GATEWAY-HTTP
# Reason: not implemented yet.
# Issue: https://github.com/Docker-Hunterpedia/ReverseDock/issues/123
skipTests:
  # Reason: HTTPRoute mirroring to several backends is not implemented yet.
  # Issue: https://github.com/Docker-Hunterpedia/ReverseDock/issues/123
  - HTTPRouteRequestMultipleMirrors
  # no reason and no link
  - HTTPRouteMethodMatching
other: value
"""

GOOD = """\
apiVersion: gateway.networking.k8s.io/v1
date: "2026-11-11T10:00:00Z"
gatewayAPIChannel: standard
gatewayAPIVersion: v1.7.0
implementation:
  contact:
  - '@Docker-Hunterpedia'
  - https://github.com/Docker-Hunterpedia/ReverseDock/issues/new/choose
  organization: Docker-Hunterpedia
  project: ReverseDock
  url: https://github.com/Docker-Hunterpedia/ReverseDock
  version: v0.7.0
kind: ConformanceReport
mode: default
profiles:
- core:
    result: success
    statistics:
      Failed: 0
      Passed: 28
      Skipped: 0
  extended:
    result: success
    statistics:
      Failed: 0
      Passed: 9
      Skipped: 0
    supportedFeatures:
    - HTTPRouteMethodMatching
    unsupportedFeatures:
    - HTTPRouteCORS
  name: GATEWAY-HTTP
  summary: Core tests succeeded. Extended tests succeeded.
- core:
    result: success
    statistics:
      Failed: 0
      Passed: 5
      Skipped: 0
  name: GATEWAY-GRPC
  summary: Core tests succeeded.
"""

CORE_FAILURE = GOOD.replace(
    "    result: success\n    statistics:\n      Failed: 0\n      Passed: 5\n      Skipped: 0\n",
    "    result: failure\n    statistics:\n      Failed: 1\n      Passed: 4\n      Skipped: 0\n"
    "    failedTests:\n    - GRPCExactMethodMatching\n",
)

PARTIAL_WITH_SKIP = GOOD.replace(
    "      Failed: 0\n      Passed: 9\n      Skipped: 0\n",
    "      Failed: 0\n      Passed: 8\n      Skipped: 1\n    skippedTests:\n    - HTTPRouteRequestMultipleMirrors\n",
).replace("    result: success\n    statistics:\n      Failed: 0\n      Passed: 8", "    result: partial\n    statistics:\n      Failed: 0\n      Passed: 8")

# GATEWAY-UDP has core features only (Gateway, ReferenceGrant, UDPRoute): no extended level.
WITH_UDP = GOOD + """- core:
    result: success
    statistics:
      Failed: 0
      Passed: 9
      Skipped: 0
  name: GATEWAY-UDP
  summary: Core tests succeeded.
"""

OPTIONS_WITH_UDP = OPTIONS.replace("  - GATEWAY-GRPC\n", "  - GATEWAY-GRPC\n  - GATEWAY-UDP\n")

NO_GRPC = GOOD.split("- core:\n    result: success\n    statistics:\n      Failed: 0\n      Passed: 5")[0]


def run(report_text, options_text=OPTIONS, allow_partial=False):
    with tempfile.TemporaryDirectory() as tmp:
        report = os.path.join(tmp, "report.yaml")
        options = os.path.join(tmp, "options.yaml")
        summary = os.path.join(tmp, "summary.md")
        with open(report, "w", encoding="utf-8") as handle:
            handle.write(report_text)
        with open(options, "w", encoding="utf-8") as handle:
            handle.write(options_text)
        argv = ["--report", report, "--options", options, "--summary", summary]
        if allow_partial:
            argv.append("--allow-partial")
        stdout = sys.stdout
        try:
            with open(os.path.join(tmp, "stdout.txt"), "w", encoding="utf-8") as sink:
                sys.stdout = sink
                code = cr.main(argv)
            with open(os.path.join(tmp, "stdout.txt"), encoding="utf-8") as handle:
                text = handle.read()
        finally:
            sys.stdout = stdout
        md = ""
        if os.path.exists(summary):
            with open(summary, encoding="utf-8") as handle:
                md = handle.read()
        return code, text, md


class CheckReport(unittest.TestCase):
    def cases(self):
        yield "pyyaml", cr.yaml
        yield "fallback", None

    def each(self, fn):
        original = cr.yaml
        try:
            for label, module in self.cases():
                if label == "pyyaml" and original is None:
                    continue
                cr.yaml = module
                with self.subTest(parser=label):
                    fn()
        finally:
            cr.yaml = original

    def test_parsers_agree(self):
        if cr.yaml is None:
            self.skipTest("PyYAML not installed")
        for text in (GOOD, CORE_FAILURE, PARTIAL_WITH_SKIP, OPTIONS, OPTIONS_WITH_SKIP):
            fallback = cr.yaml
            cr.yaml = None
            try:
                mine = cr.load_yaml(text)
            finally:
                cr.yaml = fallback
            self.assertEqual(mine, fallback.safe_load(text))

    def test_good_report(self):
        def check():
            code, text, md = run(GOOD)
            self.assertEqual(code, 0, text)
            self.assertIn("GATEWAY-HTTP", text)
            self.assertIn("| GATEWAY-GRPC | core | success | 5 | 0 | 0 |", md)
            self.assertIn("result: passed", text)
        self.each(check)

    def test_core_failure_fails_unless_partial_allowed(self):
        def check():
            code, text, _ = run(CORE_FAILURE)
            self.assertEqual(code, 1)
            self.assertIn("GATEWAY-GRPC core: failure", text)
            self.assertIn("GRPCExactMethodMatching", text)
            code, text, _ = run(CORE_FAILURE, allow_partial=True)
            self.assertEqual(code, 0)
            self.assertIn("warning: GATEWAY-GRPC core: failure", text)
        self.each(check)

    def test_a_profile_with_core_tests_only(self):
        def check():
            code, text, md = run(WITH_UDP, OPTIONS_WITH_UDP)
            self.assertEqual(code, 0, text)
            self.assertIn("| GATEWAY-UDP | core | success | 9 | 0 | 0 |", md)
            # Listed in options.yaml but absent from the report: an error.
            code, text, _ = run(GOOD, OPTIONS_WITH_UDP)
            self.assertEqual(code, 1)
            self.assertIn("profile GATEWAY-UDP is in options.yaml but not in the report", text)
        self.each(check)

    def test_missing_profile(self):
        def check():
            self.assertEqual(run(NO_GRPC)[0], 1)
            self.assertEqual(run(NO_GRPC, allow_partial=True)[0], 0)
        self.each(check)

    def test_declared_skip_that_is_in_the_report_is_fine(self):
        options = OPTIONS_WITH_SKIP.replace("  # no reason and no link\n  - HTTPRouteMethodMatching\n", "")

        def check():
            code, text, _ = run(PARTIAL_WITH_SKIP, options)
            self.assertEqual(code, 0, text)
        self.each(check)

    def test_stale_skip_and_missing_reason(self):
        def check():
            code, text, _ = run(GOOD, OPTIONS_WITH_SKIP)
            self.assertEqual(code, 1)
            self.assertIn("stale skip: HTTPRouteRequestMultipleMirrors", text)
            self.assertIn("skipTests entry HTTPRouteMethodMatching needs a reason and an issue link", text)
            self.assertNotIn("skipTests entry HTTPRouteRequestMultipleMirrors needs", text)
            # a stale skip stays an error even with --allow-partial
            self.assertEqual(run(GOOD, OPTIONS_WITH_SKIP, allow_partial=True)[0], 1)
        self.each(check)

    def test_wrong_version_and_unreadable(self):
        def check():
            self.assertEqual(run(GOOD.replace("gatewayAPIVersion: v1.7.0", "gatewayAPIVersion: v1.6.0"))[0], 1)
            self.assertEqual(run("not: a report\n")[0], 2)
            with tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(cr.main(["--report", os.path.join(tmp, "missing.yaml"), "--summary", ""]), 2)
        self.each(check)


if __name__ == "__main__":
    unittest.main()
