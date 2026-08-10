"""The security report contract: three sections, three independent statuses.

An unreachable vulnerability database must not make a successful domain scan
look absent, and a missing dependency file is ``skipped``, not ``failed``.
Downstream the Marketplace grades those differently, so collapsing them here
would silently change a plugin page.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from toolkit.scan import report as security_report


def write_plugin(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="plugin-scan-test-"))
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


class ReportTest(unittest.TestCase):
    def test_sections_carry_independent_status(self):
        """A failed lookup must not make the other sections look absent."""

        def failing_lookup(_dependencies):
            return [], "failed"

        root = write_plugin(
            {
                "tool.py": 'BASE = "https://api.vendor.com"\n',
                "requirements.txt": "requests==2.31.0\n",
            }
        )
        report = security_report.build_security_report(
            root, scanned_at="2026-08-04T00:00:00Z", vulnerability_lookup=failing_lookup
        )
        self.assertEqual(report["access_domains"]["status"], "ok")
        self.assertEqual(report["dependencies"]["status"], "failed")
        self.assertEqual(report["capabilities"]["status"], "ok")

    def test_no_dependency_file_is_skipped_not_failed(self):
        root = write_plugin({"tool.py": "x = 1\n"})
        report = security_report.build_security_report(
            root, scanned_at="2026-08-04T00:00:00Z", vulnerability_lookup=lambda _d: ([], "ok")
        )
        self.assertEqual(report["dependencies"]["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
