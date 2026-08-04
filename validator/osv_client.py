"""Dependency vulnerability lookup against the OSV database.

Stdlib only, on purpose. The two plugin repositories install exactly one
third-party package for the toolkit (``requests``) and adding a scanner binary
or a pip package would mean editing four workflow files across two repos —
which the whole design avoids. ``urllib.request`` against the public OSV REST
API gets the same data with no new dependency.

Why OSV and not ``pip-audit`` / ``osv-scanner``:

* ``pip-audit`` resolves an environment; we already have exact versions from
  ``uv.lock`` or a pinned ``requirements.txt``, so resolution is wasted work
  and a new pip dependency.
* ``osv-scanner`` is a Go binary that would need a download step in every
  workflow.

Both read the same OSV data this module queries directly.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

OSV_API = "https://api.osv.dev"
BATCH_SIZE = 500
DEFAULT_TIMEOUT = 20
DETAIL_WORKERS = 8

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

# GitHub advisories use MODERATE where the rest of the world says MEDIUM.
_SEVERITY_ALIASES = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


class OSVUnavailable(RuntimeError):
    """The database could not be reached or answered unusably."""


def _post_json(path: str, payload: dict, timeout: int) -> dict:
    request = urllib.request.Request(
        f"{OSV_API}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "dify-marketplace-toolkit"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as error:
        raise OSVUnavailable(str(error)) from error


def _get_json(path: str, timeout: int) -> dict:
    request = urllib.request.Request(
        f"{OSV_API}{path}", headers={"User-Agent": "dify-marketplace-toolkit"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as error:
        raise OSVUnavailable(str(error)) from error


def _severity_of(record: dict) -> tuple[str, str]:
    """Return ``(severity, cvss_vector)``.

    OSV itself only carries CVSS vectors; the human-readable band lives in the
    ecosystem's ``database_specific`` block, which GHSA records populate and
    PYSEC records do not. Deriving a band from a vector means implementing the
    CVSS scoring formula, so records without a band stay ``UNKNOWN`` rather
    than being guessed at — and deduplication below usually finds a GHSA twin
    that does carry one.
    """
    vector = ""
    for entry in record.get("severity") or []:
        score = entry.get("score")
        if score:
            vector = score
            break
    band = ((record.get("database_specific") or {}).get("severity") or "").upper()
    return _SEVERITY_ALIASES.get(band, "UNKNOWN"), vector


def _fixed_version(record: dict, package: str) -> str:
    for affected in record.get("affected") or []:
        name = ((affected.get("package") or {}).get("name") or "").lower()
        if name and name.replace("_", "-") != package.replace("_", "-"):
            continue
        for entry in affected.get("ranges") or []:
            for event in entry.get("events") or []:
                if event.get("fixed"):
                    return str(event["fixed"])
    return ""


def _dedupe(findings: list[dict]) -> list[dict]:
    """Collapse records that describe the same vulnerability.

    OSV returns a GHSA record and its PYSEC twin for the same CVE. Listing both
    doubles every count the rating will later read, so they are merged by
    alias-set overlap and the record with a real severity band wins.
    """
    buckets: list[dict] = []
    for finding in sorted(
        findings, key=lambda item: SEVERITY_ORDER.get(item["severity"], 0), reverse=True
    ):
        identifiers = {finding["vuln_id"], *finding["aliases"]}
        target = None
        for bucket in buckets:
            if bucket["package"] != finding["package"]:
                continue
            if bucket["version"] != finding["version"]:
                continue
            if bucket["identifiers"] & identifiers:
                target = bucket
                break
        if target is None:
            buckets.append(
                {
                    "package": finding["package"],
                    "version": finding["version"],
                    "identifiers": identifiers,
                    "finding": finding,
                }
            )
        else:
            target["identifiers"] |= identifiers
            merged = sorted(target["identifiers"] - {target["finding"]["vuln_id"]})
            target["finding"]["aliases"] = merged
            if not target["finding"]["fixed_version"] and finding["fixed_version"]:
                target["finding"]["fixed_version"] = finding["fixed_version"]

    result = [bucket["finding"] for bucket in buckets]
    result.sort(
        key=lambda item: (
            -SEVERITY_ORDER.get(item["severity"], 0),
            item["package"],
            item["vuln_id"],
        )
    )
    return result


def lookup(dependencies: list[dict], *, timeout: int = DEFAULT_TIMEOUT) -> tuple[list[dict], str]:
    """Look up ``[{name, version}]`` in OSV.

    Returns ``(vulnerabilities, status)`` where status is ``ok``, ``skipped``
    (nothing to look up) or ``failed`` (the database was unreachable). A failure
    is reported, never swallowed into an empty result — "no vulnerabilities"
    and "we could not check" must stay distinguishable all the way to the
    plugin page.
    """
    pairs = [
        (item["name"], item["version"])
        for item in dependencies
        if item.get("name") and item.get("version")
    ]
    if not pairs:
        return [], "skipped"

    matches: list[tuple[str, str, str]] = []  # (package, version, vuln_id)
    try:
        for start in range(0, len(pairs), BATCH_SIZE):
            chunk = pairs[start : start + BATCH_SIZE]
            payload = {
                "queries": [
                    {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
                    for name, version in chunk
                ]
            }
            response = _post_json("/v1/querybatch", payload, timeout)
            for (name, version), result in zip(chunk, response.get("results") or []):
                for vulnerability in result.get("vulns") or []:
                    identifier = vulnerability.get("id")
                    if identifier:
                        matches.append((name, version, identifier))
    except OSVUnavailable:
        return [], "failed"

    if not matches:
        return [], "ok"

    unique_ids = sorted({identifier for _, _, identifier in matches})
    records: dict[str, dict] = {}
    try:
        with ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as pool:
            for identifier, record in zip(
                unique_ids,
                pool.map(lambda item: _get_json(f"/v1/vulns/{item}", timeout), unique_ids),
            ):
                records[identifier] = record
    except OSVUnavailable:
        # The batch query already told us which packages are affected; losing
        # the detail fetch degrades severity to UNKNOWN rather than dropping
        # the finding.
        records = {}

    findings = []
    for package, version, identifier in matches:
        record = records.get(identifier) or {}
        severity, vector = _severity_of(record) if record else ("UNKNOWN", "")
        findings.append(
            {
                "package": package,
                "version": version,
                "vuln_id": identifier,
                "aliases": sorted(record.get("aliases") or []),
                "severity": severity,
                "cvss": vector,
                "summary": (record.get("summary") or "")[:500],
                "fixed_version": _fixed_version(record, package) if record else "",
            }
        )

    return _dedupe(findings), "ok"


def make_lookup(*, enabled: bool = True, timeout: int = DEFAULT_TIMEOUT):
    """Build the callable :func:`plugin_scan.build_security_report` expects."""
    if not enabled:
        return None

    def _lookup(dependencies: list[dict]) -> tuple[list[dict], str]:
        return lookup(dependencies, timeout=timeout)

    return _lookup
