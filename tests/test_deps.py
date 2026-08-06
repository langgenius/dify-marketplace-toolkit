"""Dependency collection, most-exact source first.

The distinction these tests protect is ``resolved`` versus ``unresolved``: a
range constraint cannot be looked up in a vulnerability database, and folding
it into a clean result would report "no known vulnerabilities" for something
nobody checked.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from toolkit.scan import deps


def write_plugin(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="plugin-scan-test-"))
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


class DependencyCollectionTest(unittest.TestCase):
    def test_pinned_requirements_resolve(self):
        files = {"requirements.txt": "requests==2.31.0\nhttpx>=0.27\n# comment\n"}
        scan = deps.collect_dependencies(write_plugin(files))
        self.assertEqual(scan.source, "requirements.txt")
        self.assertEqual(
            scan.resolved, [{"name": "requests", "version": "2.31.0", "basis": "locked"}]
        )
        self.assertEqual(scan.unresolved, [{"name": "httpx", "specifier": ">=0.27"}])

    def test_uv_lock_wins_over_requirements(self):
        """``uv.lock`` is a resolved transitive closure; prefer it when present.

        Every official plugin is uv-native and its ``requirements.txt`` is
        generated during packaging.
        """
        files = {
            "requirements.txt": "requests>=2.0\n",
            "uv.lock": '[[package]]\nname = "requests"\nversion = "2.32.3"\n',
        }
        scan = deps.collect_dependencies(write_plugin(files))
        self.assertEqual(scan.source, "uv.lock")
        self.assertEqual(
            scan.resolved, [{"name": "requests", "version": "2.32.3", "basis": "locked"}]
        )

    def test_no_dependency_manifest_is_empty_not_an_error(self):
        scan = deps.collect_dependencies(write_plugin({"main.py": "x = 1\n"}))
        self.assertEqual(scan.source, "")
        self.assertEqual(scan.resolved, [])


if __name__ == "__main__":
    unittest.main()
