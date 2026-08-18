"""The extractor's CLI contract: print one PR-body section, never fail CI.

Merge-upload workflows pipe this tool's stdout straight into
``uploader --with-changelog``, so the contract is deliberately dull: the
requested section's Markdown with template comments stripped, or nothing at
all — always exit 0. Requiring the section to exist is the pre-check's job
(:mod:`toolkit.checks.pr.body`); this tool only carries what review approved.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "extract-changelog.py"


def run(body: str, *args: str) -> str:
    with tempfile.TemporaryDirectory(prefix="extract-changelog-test-") as tmp:
        pr_body_file = Path(tmp) / "pr_body.md"
        pr_body_file.write_text(body, encoding="utf-8")
        out = subprocess.run(
            [sys.executable, str(SCRIPT), "--pr-body-file", str(pr_body_file), *args],
            capture_output=True,
            text=True,
            check=True,
        )
    return out.stdout


class ExtractChangelogTest(unittest.TestCase):
    def test_extracts_what_changed_by_default(self):
        body = (
            "## Plugin information\n- **Author**: x\n\n"
            "## What changed\n\nAdded retries.\n- fixed #12\n\n"
            "## Risk level\n- [x] Low risk\n"
        )
        self.assertEqual(run(body).strip(), "Added retries.\n- fixed #12")

    def test_strips_template_comments(self):
        body = "## What changed\n<!-- Briefly describe -->\n\nReal notes.\n"
        self.assertEqual(run(body).strip(), "Real notes.")

    def test_missing_section_prints_empty_and_exits_zero(self):
        self.assertEqual(run("## Summary\nhi\n").strip(), "")

    def test_custom_section_for_official_repo(self):
        body = "## Summary\nwhy\n\n## Release Notes\n\nOfficial notes here.\n"
        self.assertEqual(
            run(body, "--section", "Release Notes").strip(), "Official notes here."
        )


if __name__ == "__main__":
    unittest.main()
