#!/usr/bin/env python3
"""Tests of scripts/release_latest.py: SemVer precedence and the rule that `latest` never moves back.

Run: python3 -I scripts/test_release_latest.py   (standard library only)
"""

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "release_latest.py")
_spec = importlib.util.spec_from_file_location("release_latest", SCRIPT)
rl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rl)


def takes(version, tags):
    return rl.decide(version, tags)[0]


class Precedence(unittest.TestCase):
    def test_semver_spec_example_order(self):
        # semver.org, section 11: the chain of increasing precedence.
        chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.1.0",
            "2.0.0",
        ]
        keys = [rl.precedence(rl.parse(v)) for v in chain]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(set(keys)), len(keys))

    def test_numbers_are_numbers(self):
        self.assertLess(rl.precedence(rl.parse("1.9.0")), rl.precedence(rl.parse("1.10.0")))
        self.assertLess(rl.precedence(rl.parse("0.9.0-alpha.9")), rl.precedence(rl.parse("0.9.0-alpha.10")))

    def test_build_metadata_is_ignored(self):
        self.assertEqual(rl.precedence(rl.parse("1.2.3+a")), rl.precedence(rl.parse("1.2.3+b")))

    def test_v_prefix(self):
        self.assertEqual(rl.parse("v1.2.3"), rl.parse("1.2.3"))

    def test_not_semver(self):
        for text in ["1.2", "1.2.3.4", "01.2.3", "1.2.3-", "1.2.3-01", "latest", "", "vv1.2.3", "1.2.3-rc..1"]:
            self.assertIsNone(rl.parse(text), text)


class Latest(unittest.TestCase):
    def test_first_stable_release_takes_latest(self):
        self.assertTrue(takes("1.0.0", ["v0.9.0-alpha.1", "v1.0.0-rc.1", "v1.0.0"]))

    def test_new_minor_takes_latest(self):
        self.assertTrue(takes("1.4.0", ["v1.3.0", "v1.3.1", "v1.4.0"]))

    def test_new_patch_of_newest_minor_takes_latest(self):
        self.assertTrue(takes("1.4.1", ["v1.3.5", "v1.4.0", "v1.4.1"]))

    def test_patch_for_an_older_minor_does_not(self):
        self.assertFalse(takes("1.3.5", ["v1.3.4", "v1.4.0", "v1.3.5"]))

    def test_older_major_does_not(self):
        self.assertFalse(takes("1.9.9", ["v1.9.8", "v2.0.0", "v1.9.9"]))

    def test_prerelease_never_takes_latest(self):
        self.assertFalse(takes("1.0.0-rc.1", ["v0.9.0", "v1.0.0-rc.1"]))
        self.assertFalse(takes("2.0.0-rc.1", []))
        self.assertFalse(takes("0.9.0-alpha.1", ["v0.9.0-alpha.1"]))

    def test_prerelease_of_a_higher_version_does_not_hold_latest_back(self):
        self.assertTrue(takes("1.3.5", ["v1.3.4", "v1.4.0-rc.1", "v1.3.5"]))

    def test_final_release_after_its_release_candidates(self):
        self.assertTrue(takes("1.0.0", ["v1.0.0-rc.1", "v1.0.0-rc.2", "v1.0.0"]))

    def test_no_other_tags(self):
        self.assertTrue(takes("1.0.0", []))
        self.assertTrue(takes("1.0.0", ["v1.0.0"]))

    def test_rebuilding_the_current_highest_keeps_latest(self):
        self.assertTrue(takes("1.4.0", ["v1.4.0", "v1.3.0"]))

    def test_rebuilding_an_old_release_does_not(self):
        self.assertFalse(takes("1.3.0", ["v1.3.0", "v1.4.0"]))

    def test_numeric_not_lexical(self):
        self.assertFalse(takes("1.9.0", ["v1.9.0", "v1.10.0"]))
        self.assertTrue(takes("1.10.0", ["v1.9.0", "v1.10.0"]))

    def test_non_semver_tags_are_ignored_and_named(self):
        takes_latest, reason = rl.decide("1.0.0", ["v1.0.0", "vnext", "v9"])
        self.assertTrue(takes_latest)
        self.assertIn("vnext", reason)

    def test_ls_remote_and_ref_formats(self):
        lines = [
            "4d101475d8b20a2381f78447822ac1eab6504dd8\trefs/tags/v1.4.0",
            "1e69f48acb82d1966a394da916b4c1698aa569d6\trefs/tags/v1.4.0^{}",
            "refs/tags/v1.3.0",
            "",
        ]
        self.assertFalse(takes("1.3.1", lines))
        self.assertTrue(takes("1.4.1", lines))

    def test_version_with_v_prefix(self):
        self.assertTrue(takes("v1.4.0", ["v1.3.0", "v1.4.0"]))

    def test_version_must_be_semver(self):
        with self.assertRaises(ValueError):
            rl.decide("dev-abc1234", [])


class Command(unittest.TestCase):
    def run_script(self, *args, stdin=""):
        return subprocess.run(
            [sys.executable, "-I", SCRIPT, *args], input=stdin, capture_output=True, text=True, check=False
        )

    def test_stdin_true(self):
        proc = self.run_script("1.4.0", stdin="v1.3.0\nv1.4.0\n")
        self.assertEqual((proc.returncode, proc.stdout.strip()), (0, "true"))

    def test_stdin_false_has_a_reason_on_stderr(self):
        proc = self.run_script("1.3.5", stdin="v1.4.0\nv1.3.5\n")
        self.assertEqual((proc.returncode, proc.stdout.strip()), (0, "false"))
        self.assertIn("v1.4.0", proc.stderr)

    def test_tags_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "tags")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("v2.0.0\nv1.0.0\n")
            proc = self.run_script("1.0.1", "--tags-file", path)
        self.assertEqual(proc.stdout.strip(), "false")

    def test_bad_version_is_exit_2_and_prints_nothing_on_stdout(self):
        proc = self.run_script("dev-abc1234")
        self.assertEqual((proc.returncode, proc.stdout), (2, ""))

    def test_usage_errors(self):
        self.assertEqual(self.run_script().returncode, 2)
        self.assertEqual(self.run_script("1.0.0", "--tags-file").returncode, 2)
        self.assertEqual(self.run_script("--bogus").returncode, 2)


if __name__ == "__main__":
    unittest.main()
