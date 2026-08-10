"""Assembling the ``security_report`` payload the Marketplace ingests.

This is the uploader's entry point: one JSON object per plugin version carrying
domains, dependencies and capabilities. Each section has its own status because
an unreachable vulnerability database must not make a successful domain scan
look absent, and a failed sub-scan must not look like a clean one.

Every section is wrapped: a scanner crash degrades that section to
``failed`` and leaves the rest intact. Publishing a plugin must never fail
because a scanner did.
"""

from __future__ import annotations

import json
from pathlib import Path

from toolkit.scan.capabilities import scan_capabilities
from toolkit.scan.deps import collect_dependencies
from toolkit.scan.hosts import extract_access_domains, read_declared_domains, undeclared_hosts

SCANNER_VERSION = "1.0.0"

def build_security_report(
    directory: Path,
    *,
    scanned_at: str,
    vulnerability_lookup=None,
    version_resolver=None,
) -> dict:
    """Produce the ``security_report`` payload for one unpacked plugin.

    ``vulnerability_lookup`` takes the resolved dependency list and returns
    ``(vulnerabilities, status)``. It is injected so the scan works offline and
    so the network half can be tested without one.

    ``version_resolver`` takes the unresolved dependency list and returns
    ``(resolved, still_unresolved)`` — see :func:`toolkit.scan.pypi.resolve_ranges`.
    It runs after dependency collection and before the vulnerability lookup, so
    an inferred version is checked against the database like a pinned one.
    Injected for the same reason as the lookup.

    Each section carries its own status. A dependency lookup that could not
    reach the database must not make the domain scan look absent — "we did not
    scan" and "we scanned and found nothing" are different answers, and the
    rating downstream treats them differently.
    """
    report: dict = {
        "schema_version": 1,
        "scanner_version": SCANNER_VERSION,
        "scanned_at": scanned_at,
    }

    try:
        domain_scan = extract_access_domains(directory)
        declared = read_declared_domains(directory)
        detected_hosts = domain_scan.hosts()
        access = domain_scan.to_json()
        access["status"] = "ok"
        access["declared"] = declared
        access["undeclared"] = undeclared_hosts(detected_hosts, declared)
        report["access_domains"] = access
    except Exception as error:  # noqa: BLE001 - a scan crash must not block publishing
        report["access_domains"] = {"status": "failed", "error": str(error)[:200]}

    try:
        dependency_scan = collect_dependencies(directory)
        if version_resolver is not None and dependency_scan.unresolved:
            inferred, still_unresolved = version_resolver(dependency_scan.unresolved)
            dependency_scan.resolved = sorted(
                dependency_scan.resolved + inferred,
                key=lambda item: (item["name"], item["version"]),
            )
            dependency_scan.unresolved = still_unresolved
        dependencies = dependency_scan.to_json()
        dependencies["database"] = "osv.dev"
        if not dependency_scan.resolved and not dependency_scan.unresolved:
            dependencies["status"] = "skipped"
            dependencies["vulnerabilities"] = []
        elif vulnerability_lookup is None:
            dependencies["status"] = "skipped"
            dependencies["vulnerabilities"] = []
        else:
            vulnerabilities, status = vulnerability_lookup(dependency_scan.resolved)
            dependencies["status"] = status
            dependencies["vulnerabilities"] = vulnerabilities
        report["dependencies"] = dependencies
    except Exception as error:  # noqa: BLE001
        report["dependencies"] = {"status": "failed", "error": str(error)[:200]}

    try:
        categories = scan_capabilities(directory)
        report["capabilities"] = {
            "status": "ok",
            "categories": [
                {"name": item.name, "count": item.count, "samples": item.samples[:5]}
                for item in categories
            ],
        }
    except Exception as error:  # noqa: BLE001
        report["capabilities"] = {"status": "failed", "error": str(error)[:200]}

    return report


def dumps_report(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, separators=(",", ":"))
