"""Package a plugin and upload it to the Marketplace.

This script is the only toolkit entry point that every publish path already
calls: both plugin repositories invoke it from their pre-check and their
merge workflow. That makes it the one place where a static security scan can
be attached without editing a single workflow file — which is why the scan
lives here rather than as a new CI step.

The scan result travels with the package as one extra multipart field. It is
strictly additive: an older Marketplace ignores the field, and a scan that
fails for any reason is reported inside the payload rather than raised.
**Publishing a plugin must never fail because a scanner did.**
"""

import argparse
import datetime
import json
import sys
import os
import shutil
import subprocess
import tempfile
import traceback
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "validator"))

import osv_client  # noqa: E402
import plugin_scan  # noqa: E402

MARKETPLACE_BASE_URL = ""
PLUGIN_DAEMON_PATH = "./dify-plugin"
TESTING = False
SCAN_VULNERABILITIES = True


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


def build_security_report(package: str) -> str:
    """Scan the packaged artifact and serialise the Marketplace payload.

    The *package* is scanned rather than the source directory so the report
    describes exactly what gets published. It matters for the official plugin
    repository, whose ``requirements.txt`` is generated during packaging and
    does not exist in the source tree.

    Any failure degrades to an empty string: the upload proceeds without the
    field, exactly as it did before this existed.
    """
    workdir = None
    try:
        workdir = tempfile.mkdtemp(prefix="plugin-security-scan-")
        unpacked = Path(workdir) / "unpacked"
        unpacked.mkdir(parents=True, exist_ok=True)
        plugin_scan.unpack_package(Path(package), unpacked)
        report = plugin_scan.build_security_report(
            unpacked,
            scanned_at=datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            vulnerability_lookup=osv_client.make_lookup(enabled=SCAN_VULNERABILITIES),
        )
        print(f"Security scan: {summarize_report(report)}")
        return plugin_scan.dumps_report(report)
    except Exception:
        print("Security scan failed; uploading without a security report")
        print(traceback.format_exc())
        return ""
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
    global TESTING

    # Deliberately before the testing guard: the pre-check workflows run this
    # script with --test, and that is where an author should first see what
    # the plugin page will say about their package.
    security_report = build_security_report(package)

    if TESTING:
        print("!!! Skip uploading package in testing")
        return

    url = f"{base_url}/api/v1/plugins/inner-upload"

    payload = {
        "changelog": changelog,
        "forcely": 'true' if force else 'false',
    }
    if security_report:
        payload["security_report"] = security_report

    files = [
        ("file", (package, open(package, "rb"), "application/octet-stream"))
    ]

    headers = {
        "Authorization": f"Bearer {token}"
    }

    resp = requests.post(url, headers=headers, data=payload, files=files)
    print(resp.json())
    if resp.status_code != 200 or resp.json().get("code") != 0:
        raise Exception(f"Failed to upload package: {resp.json()}")


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
