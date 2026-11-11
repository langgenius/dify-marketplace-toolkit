import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "validator" / "check-pkg-paths.py"


def run_script(files):
    env = dict(os.environ, PR_FILES=json.dumps(files))
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


class CheckPkgPathsTest(unittest.TestCase):
    def test_stdout_carries_only_the_primary_path(self):
        # Removing older versions next to the new package is allowed, and the
        # note about it must not share stdout with the answer: both plugin
        # repositories capture stdout into $GITHUB_ENV.
        result = run_script([
            {"path": "author/plugin/plugin-0.1.0.difypkg", "changeType": "DELETED"},
            {"path": "author/plugin/plugin-0.2.0.difypkg", "changeType": "ADDED"},
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "author/plugin/plugin-0.2.0.difypkg\n")
        self.assertIn("also removing 1 older version(s)", result.stderr)

    def test_raw_api_status_field_is_supported(self):
        result = run_script([
            {"path": "author/plugin/plugin-0.1.0.difypkg", "status": "removed"},
            {"path": "author/plugin/plugin-0.2.0.difypkg", "status": "added"},
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "author/plugin/plugin-0.2.0.difypkg\n")

    def test_two_plugins_in_one_pr_are_rejected(self):
        result = run_script([
            {"path": "a/x-1.0.0.difypkg", "changeType": "ADDED"},
            {"path": "b/y-1.0.0.difypkg", "changeType": "ADDED"},
        ])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("only one plugin (directory) is allowed", result.stderr)

    def test_removal_only_pr_is_rejected(self):
        result = run_script([
            {"path": "author/plugin/plugin-0.1.0.difypkg", "changeType": "DELETED"},
        ])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("exactly one added or modified .difypkg", result.stderr)
