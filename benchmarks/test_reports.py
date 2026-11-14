"""Tests for report.py and hosted_report.py: python3 -I benchmarks/test_reports.py"""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import hosted_report  # noqa: E402
import report  # noqa: E402


def run(proxy, rate=5000, p99=1.0, negotiated=None):
    r = {
        "proxy": proxy,
        "rate": rate,
        "duration": "30s",
        "requests": rate * 30,
        "achieved_rps": rate,
        "failed": 0.0,
        "dropped": 0,
        "ms": {"p50": 0.3, "p90": 0.5, "p99": p99, "p999": 2.0, "max": 9.0},
    }
    if negotiated is not None:
        r["negotiated"] = negotiated
    return r


def negotiated(checked=100, proto=0, tls=0, cipher=0):
    return {
        "expected": {"proto": "HTTP/2.0", "tls": "tls1.3", "cipher": "TLS_AES_128_GCM_SHA256"},
        "checked": checked,
        "wrong_proto": proto,
        "wrong_tls": tls,
        "wrong_cipher": cipher,
    }


class ReportTest(unittest.TestCase):
    def test_plain_scenarios_keep_the_old_table(self):
        out = report.render([run("rdock"), run("nginx", p99=0.5)])
        lines = out.splitlines()
        self.assertNotIn("Negotiated", lines[0])
        self.assertTrue(lines[2].startswith("| nginx |"), "sorted by p99")
        self.assertEqual(len(lines), 4)

    def test_parity_ok(self):
        out = report.render([run("rdock", negotiated=negotiated())])
        self.assertIn("Negotiated", out)
        self.assertIn("ok (100 checked)", out)
        self.assertNotIn("parity mismatch", out)

    def test_parity_mismatch_names_what_differed(self):
        out = report.render([run("caddy", negotiated=negotiated(proto=3, cipher=100))])
        self.assertIn("parity mismatch: 3/100 not HTTP/2.0, 100/100 not TLS_AES_128_GCM_SHA256", out)

    def test_nothing_checked_is_a_mismatch(self):
        self.assertIn("parity mismatch: nothing checked", report.render([run("x", negotiated=negotiated(checked=0))]))


class HostedReportTest(unittest.TestCase):
    def test_states_the_limits_and_joins_every_scenario(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "report.md").write_text("SINGLE TABLE\n")
            (root / "machine.txt").write_text("CPUs: 4\n")
            (root / "images.txt").write_text("nginx:1.30.6-alpine@sha256:abc nginx@sha256:abc\n")
            (root / "h2").mkdir()
            (root / "h2" / "report.md").write_text("H2 TABLE\n")
            (root / "empty").mkdir()
            out = hosted_report.render(root)
        self.assertIn("A free GitHub-hosted runner, not dedicated hardware", out)
        self.assertIn("What a dedicated three-machine run would add (open)", out)
        self.assertIn("CPUs: 4", out)
        self.assertIn("nginx@sha256:abc", out)
        self.assertLess(out.index("## single"), out.index("## h2"))
        self.assertIn("H2 TABLE", out)
        self.assertNotIn("## empty", out)

    def test_no_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = hosted_report.render(tmp)
        self.assertIn("No results found.", out)
        self.assertIn("Read with care", out)


if __name__ == "__main__":
    unittest.main()
