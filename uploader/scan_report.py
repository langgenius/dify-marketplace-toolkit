"""Build and submit the scan report: ``PUT /api/v1/plugin-artifacts/{checksum}/scan-report``.

The report is addressed by the artifact checksum the upload returned and
travels as its own call after the package is published. Nothing in here may
fail the job: the package is live by the time the report travels, and a red
merge workflow invites a re-run that uploads the package again. So every
failure degrades to a ``::warning::`` annotation. Server errors and timeouts
are retried; a 4xx is a contract disagreement a retry cannot fix.
"""

from __future__ import annotations

import datetime
import shutil
import tempfile
import time
import traceback
from pathlib import Path

import requests

from toolkit import osv
from toolkit.scan import pypi
from toolkit.scan import report as security_scan
from toolkit.walk import unpack_package

SCHEMA_VERSION = 1
PRODUCER = "ci"
ATTEMPTS = 3
# (connect, read). The report is a small JSON body; it must not hang a workflow.
TIMEOUT = (5, 30)


def utc_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def warn(message: str):
    # GitHub Actions renders `::warning::` as an annotation; locally it is a
    # prefixed line. Either way the failure is visible without being able to
    # fail the job.
    print(f"::warning::{message}")


def build(package: str, scan_vulnerabilities: bool = True):
    """Scan the packaged artifact and return the report payload, or None.

    The *package* is scanned rather than the source directory so the report
    describes exactly what gets published. It matters for the official plugin
    repository, whose ``requirements.txt`` is generated during packaging and
    does not exist in the source tree.

    Any failure degrades to ``None``: the publish proceeds without a report,
    exactly as it did before the scanner existed.
    """
    workdir = None
    try:
        workdir = tempfile.mkdtemp(prefix="plugin-security-scan-")
        unpacked = Path(workdir) / "unpacked"
        unpacked.mkdir(parents=True, exist_ok=True)
        unpack_package(Path(package), unpacked)
        report = security_scan.build_security_report(
            unpacked,
            scanned_at=utc_now(),
            vulnerability_lookup=osv.make_lookup(enabled=scan_vulnerabilities),
            # Range inference queries PyPI, so it obeys the same switch as the
            # vulnerability lookup: --no-vuln-scan keeps the scan fully offline,
            # while --test still resolves and queries — that run is exactly
            # where an author first sees what the plugin page will say.
            version_resolver=pypi.make_resolver(enabled=scan_vulnerabilities),
        )
        print(f"Security scan: {summarize(report)}")
        return report
    except Exception:
        print("Security scan failed")
        print(traceback.format_exc())
        return None
    finally:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)


def summarize(report: dict) -> str:
    domains = report.get("access_domains") or {}
    dependencies = report.get("dependencies") or {}
    capabilities = report.get("capabilities") or {}
    return (
        f"{len(domains.get('detected') or [])} domain(s), "
        f"{len(domains.get('undeclared') or [])} undeclared, "
        f"{domains.get('runtime_constructed', 0)}/{domains.get('network_callsites', 0)} "
        f"runtime-constructed call site(s); "
        f"dependencies={dependencies.get('status', 'unknown')} "
        f"({len(dependencies.get('vulnerabilities') or [])} vulnerability findings); "
        f"capabilities={len(capabilities.get('categories') or [])} categor(ies)"
    )


def submit(package: str, checksum: str, token: str, base_url: str, scan_vulnerabilities: bool = True):
    """Scan the artifact and submit the result against its checksum."""
    try:
        if not checksum:
            warn("upload response carried no artifact checksum; scan report not submitted")
            return

        report = build(package, scan_vulnerabilities)
        if report is None:
            warn("security scan failed; scan report not submitted")
            return

        body = {
            "schema_version": SCHEMA_VERSION,
            "producer": PRODUCER,
            "produced_at": utc_now(),
            **report,
        }
        url = f"{base_url}/api/v1/plugin-artifacts/{checksum}/scan-report"
        headers = {"Authorization": f"Bearer {token}"}

        failure = ""
        for attempt in range(ATTEMPTS):
            if attempt:
                time.sleep(2 ** attempt)
            try:
                resp = requests.put(url, headers=headers, json=body, timeout=TIMEOUT)
            except requests.RequestException as error:
                failure = f"scan report submission failed: {error}"
                continue
            if resp.status_code >= 500:
                failure = f"scan report submission failed: HTTP {resp.status_code}"
                continue
            if resp.status_code != 200:
                warn(f"scan report rejected with HTTP {resp.status_code}: {resp.text[:200]}")
                return
            try:
                result = resp.json().get("data")
            except ValueError:
                result = None
            print(f"Scan report submitted: {result}")
            return
        warn(failure)
    except Exception:
        warn("scan report submission crashed; the publish is unaffected")
        print(traceback.format_exc())
