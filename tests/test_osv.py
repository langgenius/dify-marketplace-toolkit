"""OSV lookup behaviour, pinned against canned API responses.

OSV returns a GHSA record and its PYSEC twin for the same CVE, GitHub spells
MEDIUM as MODERATE, and often only one twin knows the fixed version. Each test
here injects a fake transport in place of ``_post_json`` / ``_get_json`` and
asserts the merge rules that keep the Marketplace counts honest — offline, so
they hold when the recorded responses drift from what the live API says today.
"""

from __future__ import annotations

import unittest
from unittest import mock

from toolkit import osv


def fake_transport(vulns_by_query: dict[tuple[str, str], list[str]], records: dict[str, dict]):
    """Build ``(_post_json, _get_json)`` doubles serving fixed fixtures."""

    def post_json(path: str, payload: dict, timeout: int) -> dict:
        assert path == "/v1/querybatch"
        results = []
        for query in payload["queries"]:
            key = (query["package"]["name"], query["version"])
            results.append({"vulns": [{"id": vuln_id} for vuln_id in vulns_by_query.get(key, [])]})
        return {"results": results}

    def get_json(path: str, timeout: int) -> dict:
        identifier = path.rsplit("/", 1)[1]
        return records[identifier]

    return post_json, get_json


def run_lookup(dependencies, vulns_by_query, records):
    post_json, get_json = fake_transport(vulns_by_query, records)
    with mock.patch.object(osv, "_post_json", post_json), mock.patch.object(
        osv, "_get_json", get_json
    ):
        return osv.lookup(dependencies)


class AliasDeduplicationTest(unittest.TestCase):
    def test_ghsa_and_pysec_twins_merge_and_higher_severity_wins(self):
        """One CVE, two records; listing both would double every count."""
        findings, status = run_lookup(
            [{"name": "requests", "version": "2.30.0"}],
            {("requests", "2.30.0"): ["GHSA-aaaa-bbbb-cccc", "PYSEC-2023-100"]},
            {
                "GHSA-aaaa-bbbb-cccc": {
                    "aliases": ["CVE-2023-1000", "PYSEC-2023-100"],
                    "database_specific": {"severity": "HIGH"},
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
                    "summary": "Leaks credentials on redirect",
                },
                "PYSEC-2023-100": {
                    "aliases": ["CVE-2023-1000"],
                    "summary": "Leaks credentials on redirect",
                },
            },
        )
        self.assertEqual(status, "ok")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["vuln_id"], "GHSA-aaaa-bbbb-cccc")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["aliases"], ["CVE-2023-1000", "PYSEC-2023-100"])

    def test_fixed_version_survives_merge_from_either_twin(self):
        """Only the PYSEC twin knows the fix; merging must not lose it."""
        findings, _ = run_lookup(
            [{"name": "requests", "version": "2.30.0"}],
            {("requests", "2.30.0"): ["GHSA-aaaa-bbbb-cccc", "PYSEC-2023-100"]},
            {
                "GHSA-aaaa-bbbb-cccc": {
                    "aliases": ["CVE-2023-1000", "PYSEC-2023-100"],
                    "database_specific": {"severity": "HIGH"},
                },
                "PYSEC-2023-100": {
                    "aliases": ["CVE-2023-1000"],
                    "affected": [
                        {
                            "package": {"name": "requests"},
                            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}],
                        }
                    ],
                },
            },
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["fixed_version"], "2.31.0")


class SeverityNormalisationTest(unittest.TestCase):
    def test_github_moderate_becomes_medium(self):
        findings, _ = run_lookup(
            [{"name": "idna", "version": "3.6"}],
            {("idna", "3.6"): ["GHSA-dddd-eeee-ffff"]},
            {
                "GHSA-dddd-eeee-ffff": {
                    "aliases": [],
                    "database_specific": {"severity": "Moderate"},
                }
            },
        )
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_unknown_band_stays_unknown_not_guessed(self):
        """A CVSS vector without a band must not be scored locally."""
        findings, _ = run_lookup(
            [{"name": "idna", "version": "3.6"}],
            {("idna", "3.6"): ["PYSEC-2024-1"]},
            {
                "PYSEC-2024-1": {
                    "aliases": [],
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
                }
            },
        )
        self.assertEqual(findings[0]["severity"], "UNKNOWN")
        self.assertEqual(findings[0]["cvss"], "CVSS:3.1/AV:N/AC:L")


class QueryKeyTest(unittest.TestCase):
    def test_same_package_different_versions_stay_distinct(self):
        """The lookup key is (package, version), not the package alone.

        Range inference can move a package's version between two scans of the
        same plugin; the finding for one version must never be served for the
        other. There is no response cache in :mod:`toolkit.osv` today — this
        pins the query and merge keys so adding one keeps the same contract.
        """
        seen_queries: list[tuple[str, str]] = []
        record = {"aliases": [], "database_specific": {"severity": "HIGH"}}

        def post_json(path: str, payload: dict, timeout: int) -> dict:
            results = []
            for query in payload["queries"]:
                seen_queries.append((query["package"]["name"], query["version"]))
                results.append({"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]})
            return {"results": results}

        with mock.patch.object(osv, "_post_json", post_json), mock.patch.object(
            osv, "_get_json", lambda path, timeout: record
        ):
            findings, status = osv.lookup(
                [
                    {"name": "urllib3", "version": "1.26.19"},
                    {"name": "urllib3", "version": "2.2.2"},
                ]
            )
        self.assertEqual(status, "ok")
        self.assertEqual(seen_queries, [("urllib3", "1.26.19"), ("urllib3", "2.2.2")])
        self.assertEqual(len(findings), 2)
        self.assertEqual(
            {(item["package"], item["version"]) for item in findings},
            {("urllib3", "1.26.19"), ("urllib3", "2.2.2")},
        )


if __name__ == "__main__":
    unittest.main()
