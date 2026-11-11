"""Top-level manifest version extraction for the version-update PR check."""

from __future__ import annotations

import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from toolkit.checks.pr import version_update

META_BEFORE_TOP_LEVEL = """\
author: example
name: deepinfra
meta:
  arch:
    - amd64
    - arm64
  runner:
    language: python
    version: '3.12'
    entrypoint: main
  version: '0.0.1'
plugins:
  models:
    - provider/deepinfra.yaml
type: plugin
version: 0.0.1
"""

TOP_LEVEL_FIRST = """\
version: 1.2.3
author: example
name: sample
meta:
  runner:
    version: '3.11'
"""

QUOTED_TOP_LEVEL = """\
meta:
  runner:
    version: "3.12"
version: "2.0.0-rc1"
"""


class VersionFromTextTest(unittest.TestCase):
    def test_nested_runner_version_before_top_level(self):
        self.assertEqual(version_update.version_from_text(META_BEFORE_TOP_LEVEL), "0.0.1")

    def test_top_level_version_first(self):
        self.assertEqual(version_update.version_from_text(TOP_LEVEL_FIRST), "1.2.3")

    def test_quoted_top_level_version(self):
        self.assertEqual(version_update.version_from_text(QUOTED_TOP_LEVEL), "2.0.0-rc1")


class VersionFromPackageTest(unittest.TestCase):
    def test_reads_top_level_version_from_embedded_manifest(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("manifest.yaml", META_BEFORE_TOP_LEVEL)
        path = Path(tempfile.mkdtemp(prefix="version-update-test-")) / "plugin-0.0.1.difypkg"
        path.write_bytes(buffer.getvalue())
        self.assertEqual(version_update.version_from_package(path), "0.0.1")

