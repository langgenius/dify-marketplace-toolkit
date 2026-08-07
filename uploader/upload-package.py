"""Package a plugin and upload it to the Marketplace.

This script is the only toolkit entry point that every publish path already
calls: both plugin repositories invoke it from their pre-check and their
merge workflow. That makes it the one place where the publish flow can carry
a static security scan without editing a single workflow file.

Publishing takes two calls. The upload happens first and alone decides
success; the packaged artifact is then scanned and the report is submitted
against the checksum the upload response assigned to it. A report that fails
to build or to arrive only costs the plugin page its scan data until a
rescan. **Publishing a plugin must never fail because a scanner did.**
"""

import argparse
import datetime
import json
import sys
import os
import shutil
import subprocess
import tempfile
import time
import traceback
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from toolkit import osv  # noqa: E402
from toolkit.scan import pypi  # noqa: E402
from toolkit.scan import report as security_scan  # noqa: E402
from toolkit.walk import unpack_package  # noqa: E402

MARKETPLACE_BASE_URL = ""
PLUGIN_DAEMON_PATH = "./dify-plugin"
TESTING = False
SCAN_VULNERABILITIES = True

SCAN_REPORT_SCHEMA_VERSION = 1
SCAN_REPORT_PRODUCER = "ci"
SCAN_REPORT_ATTEMPTS = 3
# (connect, read). The upload read timeout is generous because packages can be
# large; the report is a small JSON body and must not hang a workflow.
UPLOAD_TIMEOUT = (5, 300)
SCAN_REPORT_TIMEOUT = (5, 30)


def main():
    global MARKETPLACE_BASE_URL
    global PLUGIN_DAEMON_PATH
    parser = argparse.ArgumentParser(description="Upload a package or directory to the marketplace. Choose one of the following sources: -p(--package), -d(--directory), --batch-directory")
    # -p, --package
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--package", type=str, help="The package to upload")
    group.add_argument("-d", "--directory", type=str, help="The directory to package and upload")
    group.add_argument("--batch-directory", type=str, help="Batch upload all directories in the given directory")
    parser.add_argument("-t", "--token", type=str, required=True, help="The token to use for authentication")
    parser.add_argument("-u", "--base-url", type=str, help="The base url to use for the request")
    parser.add_argument("-f", "--force", action="store_true", help="Force upload the package, ignore version check")
    parser.add_argument("--with-changelog", action="store_true", help="Whether to read changelog from stdin")
    parser.add_argument("--plugin-daemon-path", type=str, help="The path to the plugin daemon")
    parser.add_argument("--test", action="store_true", help="Indicates that this is a testing")
    parser.add_argument(
        "--no-vuln-scan",
        action="store_true",
        help="Collect dependencies but do not query the vulnerability database",
    )
    args = parser.parse_args()

    if args.plugin_daemon_path:
        PLUGIN_DAEMON_PATH = args.plugin_daemon_path

    global TESTING
    global SCAN_VULNERABILITIES
    TESTING = args.test
    SCAN_VULNERABILITIES = not args.no_vuln_scan

    # if --with-changelog == true, read changelog from stdin
    if args.with_changelog:
        changelog = sys.stdin.read()
        args.changelog = changelog.strip()
    else:
        args.changelog = ""

    print(json.dumps(args.__dict__, indent=2))

    if args.base_url:
        MARKETPLACE_BASE_URL = args.base_url

    if args.package:
        upload_package(args.package, args.token, MARKETPLACE_BASE_URL, args.force, args.changelog)
    elif args.directory:
        upload_directory(args.directory, args.token, MARKETPLACE_BASE_URL, args.force, args.changelog)
    elif args.batch_directory:
        batch_upload_directory(args.batch_directory, args.token, MARKETPLACE_BASE_URL, args.force, args.changelog)
    else:
        print("No package or directory provided")


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


def build_security_report(package: str):
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
            vulnerability_lookup=osv.make_lookup(enabled=SCAN_VULNERABILITIES),
            # Range inference queries PyPI, so it obeys the same switch as the
            # vulnerability lookup: --no-vuln-scan keeps the scan fully offline,
            # while --test still resolves and queries — that run is exactly
            # where an author first sees what the plugin page will say.
            version_resolver=pypi.make_resolver(enabled=SCAN_VULNERABILITIES),
        )
        print(f"Security scan: {summarize_report(report)}")
        return report
    except Exception:
        print("Security scan failed")
        print(traceback.format_exc())
        return None
    finally:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)


def summarize_report(report: dict) -> str:
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


def upload_package(package: str, token: str, base_url: str, force: bool, changelog: str):
    if TESTING:
        # A pre-check run is where an author first sees what the plugin page
        # will say, so the scan still runs — there is just nothing published
        # and therefore no checksum to submit a report against.
        build_security_report(package)
        print("!!! Skip uploading package in testing")
        return

    checksum = post_package(package, token, base_url, force, changelog)
    submit_scan_report(package, checksum, token, base_url)


def post_package(package: str, token: str, base_url: str, force: bool, changelog: str) -> str:
    """Upload the package; return the checksum Marketplace assigned to it.

    Upload failures raise: unlike the scan report, a failed publish must be
    loud. The checksum comes from the response because the signed artifact is
    rebuilt server-side — the local bytes cannot predict it.
    """
    url = f"{base_url}/api/v1/plugins/inner-upload"

    payload = {
        "changelog": changelog,
        "forcely": 'true' if force else 'false',
    }

    files = [
        ("file", (package, open(package, "rb"), "application/octet-stream"))
    ]

    headers = {
        "Authorization": f"Bearer {token}"
    }

    resp = requests.post(url, headers=headers, data=payload, files=files, timeout=UPLOAD_TIMEOUT)
    body = resp.json()
    print(body)
    if resp.status_code != 200 or body.get("code") != 0:
        raise Exception(f"Failed to upload package: {body}")

    version = (body.get("data") or {}).get("version") or {}
    return str(version.get("checksum") or "")


def submit_scan_report(package: str, checksum: str, token: str, base_url: str):
    """Scan the artifact and submit the result against its checksum.

    Nothing here may fail the job: the package is already published, so a
    lost report only costs the plugin page its scan data until a rescan —
    while a red merge workflow invites a re-run, and a re-run uploads the
    package again. Server errors and timeouts are retried; a 4xx is a
    contract disagreement a retry cannot fix.
    """
    try:
        if not checksum:
            warn("upload response carried no artifact checksum; scan report not submitted")
            return

        report = build_security_report(package)
        if report is None:
            warn("security scan failed; scan report not submitted")
            return

        body = {
            "schema_version": SCAN_REPORT_SCHEMA_VERSION,
            "producer": SCAN_REPORT_PRODUCER,
            "produced_at": utc_now(),
            **report,
        }
        url = f"{base_url}/api/v1/plugin-artifacts/{checksum}/scan-report"
        headers = {"Authorization": f"Bearer {token}"}

        failure = ""
        for attempt in range(SCAN_REPORT_ATTEMPTS):
            if attempt:
                time.sleep(2 ** attempt)
            try:
                resp = requests.put(url, headers=headers, json=body, timeout=SCAN_REPORT_TIMEOUT)
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


def upload_directory(directory: str, token: str, base_url: str, force: bool, changelog: str):
    check_plugin_daemon_command_exists()

    # delete temp.difypkg if exists
    if os.path.exists("temp.difypkg"):
        os.remove("temp.difypkg")

    # ./dify-plugin-daemon plugin package <directory> --out temp.difypkg
    result = subprocess.run([PLUGIN_DAEMON_PATH, "plugin", "package", directory, "-o", "temp.difypkg"], capture_output=True, text=True)
    print(result.stdout)
    print(result.stderr)
    if result.returncode != 0:
        raise Exception("Failed to package the directory")
    
    upload_package("temp.difypkg", token, base_url, force, changelog)


def batch_upload_directory(directory: str, token: str, base_url: str, force: bool, changelog: str):
    success_dirs = []
    failed_dirs = []
    for dir in os.listdir(directory):
        path = os.path.join(directory, dir)
        print(f"* Uploading directory: {path}")
        try:
            upload_directory(path, token, base_url, force, changelog)
            success_dirs.append(path)
        except Exception as e:
            print(f"** Failed to upload directory: {path}")
            print(traceback.format_exc())
            failed_dirs.append(path)

    if len(failed_dirs) > 0:
        success_dirs_str = "\n ".join(success_dirs)
        failed_dirs_str = "\n ".join(failed_dirs)
        raise Exception(f"!!! Done.\nFailed directories({len(failed_dirs)}):\n {failed_dirs_str}\n\nSuccess directories({len(success_dirs)}):\n {success_dirs_str}")
    else:
        print("!!! Done.")


def check_plugin_daemon_command_exists():
    # ./daemon version
    result = subprocess.run([PLUGIN_DAEMON_PATH, "version"], capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        raise Exception("Plugin daemon command not found")


if __name__ == "__main__":
    main()
