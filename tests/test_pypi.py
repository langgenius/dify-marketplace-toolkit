"""Range inference: the version a fresh install would pick, or nothing.

The contract these tests protect is the ``basis`` split the Marketplace reads:
``locked`` versions come from the plugin's own files, ``range_inferred`` ones
from the index at scan time and carry their original ``specifier``, and
``unresolved`` narrows to "no version could be determined at all". Guessing —
a pre-release, an unparsable constraint read as "anything", a network error
folded into a clean answer — is the failure mode everything here forbids.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from toolkit.scan import pypi
from toolkit.scan import report as security_report


def fake_fetch(versions_by_package: dict[str, list[str]]):
    """A PyPI JSON API double serving a fixed version table."""

    def fetch(name: str) -> dict:
        if name not in versions_by_package:
            raise OSError(f"404 for {name}")
        return {"releases": {version: [{}] for version in versions_by_package[name]}}

    return fetch


def write_plugin(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="plugin-scan-test-"))
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


class RangeInferenceTest(unittest.TestCase):
    def test_lower_bound_picks_latest_final_release(self):
        """``>=2.0`` resolves to the newest final version, never a pre-release."""
        fetch = fake_fetch({"requests": ["2.0.0", "2.31.0", "3.0.0a1"]})
        resolved, unresolved = pypi.resolve_ranges(
            [{"name": "requests", "specifier": ">=2.0"}], fetch=fetch
        )
        self.assertEqual(unresolved, [])
        self.assertEqual(
            resolved,
            [
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "basis": "range_inferred",
                    "specifier": ">=2.0",
                }
            ],
        )

    def test_upper_bound_is_respected(self):
        fetch = fake_fetch({"urllib3": ["1.0.0", "1.26.19", "2.2.2"]})
        resolved, unresolved = pypi.resolve_ranges(
            [{"name": "urllib3", "specifier": ">=1.0,<2"}], fetch=fetch
        )
        self.assertEqual(unresolved, [])
        self.assertEqual(resolved[0]["version"], "1.26.19")

    def test_exclusion_and_wildcard_clauses(self):
        fetch = fake_fetch({"pkg": ["2.0.0", "2.1.0", "2.1.5", "3.0.0"]})
        resolved, _ = pypi.resolve_ranges(
            [{"name": "pkg", "specifier": "==2.1.*,!=2.1.5"}], fetch=fetch
        )
        self.assertEqual(resolved[0]["version"], "2.1.0")

    def test_compatible_release_clause(self):
        """``~=2.2`` means >=2.2 within the 2.x series."""
        fetch = fake_fetch({"pkg": ["2.1.0", "2.9.3", "3.0.0"]})
        resolved, _ = pypi.resolve_ranges([{"name": "pkg", "specifier": "~=2.2"}], fetch=fetch)
        self.assertEqual(resolved[0]["version"], "2.9.3")

    def test_unparsable_specifier_stays_unresolved(self):
        """URL references and environment markers must not be read as "anything"."""
        items = [
            {"name": "pkg", "specifier": "@ https://example.com/pkg.tar.gz"},
            {"name": "other", "specifier": '>=1.0; python_version < "3.11"'},
        ]
        fetch = fake_fetch({"pkg": ["9.0.0"], "other": ["9.0.0"]})
        resolved, unresolved = pypi.resolve_ranges(items, fetch=fetch)
        self.assertEqual(resolved, [])
        self.assertEqual(unresolved, items)

    def test_fetch_failure_stays_unresolved(self):
        """A network error is "could not check", never an inferred version."""

        def broken_fetch(name: str) -> dict:
            raise TimeoutError("timed out")

        resolved, unresolved = pypi.resolve_ranges(
            [{"name": "requests", "specifier": ">=2.0"}], fetch=broken_fetch
        )
        self.assertEqual(resolved, [])
        self.assertEqual(unresolved, [{"name": "requests", "specifier": ">=2.0"}])

    def test_only_prereleases_available_stays_unresolved(self):
        fetch = fake_fetch({"pkg": ["1.0.0a1", "1.0.0rc1", "2.0.0.dev1", "1.0.0.post1"]})
        resolved, unresolved = pypi.resolve_ranges(
            [{"name": "pkg", "specifier": ">=1.0"}], fetch=fetch
        )
        self.assertEqual(resolved, [])
        self.assertEqual(unresolved, [{"name": "pkg", "specifier": ">=1.0"}])


class ReportBasisContractTest(unittest.TestCase):
    def test_report_carries_basis_and_specifier(self):
        """The JSON shape the Marketplace ingests: locked vs range_inferred."""
        root = write_plugin(
            {"requirements.txt": "requests==2.31.0\nurllib3>=1.26\n"}
        )
        fetch = fake_fetch({"urllib3": ["1.26.0", "1.26.19", "2.0.0a1"]})
        seen_by_lookup: list[dict] = []

        def lookup(dependencies: list[dict]):
            seen_by_lookup.extend(dependencies)
            return [], "ok"

        report = security_report.build_security_report(
            root,
            scanned_at="2026-08-06T00:00:00Z",
            vulnerability_lookup=lookup,
            version_resolver=lambda unresolved: pypi.resolve_ranges(unresolved, fetch=fetch),
        )
        dependencies = report["dependencies"]
        self.assertEqual(dependencies["status"], "ok")
        self.assertEqual(
            dependencies["resolved"],
            [
                {"name": "requests", "version": "2.31.0", "basis": "locked"},
                {
                    "name": "urllib3",
                    "version": "1.26.19",
                    "basis": "range_inferred",
                    "specifier": ">=1.26",
                },
            ],
        )
        self.assertEqual(dependencies["unresolved"], [])
        # The inferred package joins the vulnerability query alongside the
        # locked one — inference exists so it can be checked at all.
        self.assertEqual(
            [(item["name"], item["version"]) for item in seen_by_lookup],
            [("requests", "2.31.0"), ("urllib3", "1.26.19")],
        )

    def test_unresolvable_range_keeps_unresolved_shape(self):
        root = write_plugin({"requirements.txt": "mystery>=9000\n"})
        fetch = fake_fetch({"mystery": ["1.0.0"]})
        report = security_report.build_security_report(
            root,
            scanned_at="2026-08-06T00:00:00Z",
            vulnerability_lookup=lambda _deps: ([], "ok"),
            version_resolver=lambda unresolved: pypi.resolve_ranges(unresolved, fetch=fetch),
        )
        self.assertEqual(
            report["dependencies"]["unresolved"],
            [{"name": "mystery", "specifier": ">=9000"}],
        )


if __name__ == "__main__":
    unittest.main()
