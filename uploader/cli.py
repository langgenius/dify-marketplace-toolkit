"""Command line surface for publishing plugins to the Marketplace.

Publishing takes two calls. The upload happens first and alone decides
success (``inner_upload``); the packaged artifact is then scanned and the
report is submitted against the checksum the upload response assigned to it
(``scan_report``). A report that fails to build or to arrive only costs the
plugin page its scan data until a rescan. **Publishing a plugin must never
fail because a scanner did.**

Both plugin repositories invoke this from their pre-check (``--test``) and
merge workflows by running the package directory: ``python3 .scripts/uploader``.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import subprocess
import sys
import traceback

from uploader import inner_upload, scan_report


@dataclasses.dataclass
class Options:
    token: str
    base_url: str
    force: bool
    changelog: str
    testing: bool
    scan_vulnerabilities: bool
    plugin_daemon_path: str


def main():
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

    # if --with-changelog == true, read changelog from stdin
    if args.with_changelog:
        changelog = sys.stdin.read()
        args.changelog = changelog.strip()
    else:
        args.changelog = ""

    print(json.dumps(args.__dict__, indent=2))

    options = Options(
        token=args.token,
        base_url=args.base_url or "",
        force=args.force,
        changelog=args.changelog,
        testing=args.test,
        scan_vulnerabilities=not args.no_vuln_scan,
        plugin_daemon_path=args.plugin_daemon_path or "./dify-plugin",
    )

    if args.package:
        publish_package(args.package, options)
    elif args.directory:
        publish_directory(args.directory, options)
    elif args.batch_directory:
        batch_publish_directory(args.batch_directory, options)
    else:
        print("No package or directory provided")


def publish_package(package: str, options: Options):
    if options.testing:
        # A pre-check run is where an author first sees what the plugin page
        # will say, so the scan still runs — there is just nothing published
        # and therefore no checksum to submit a report against.
        scan_report.build(package, options.scan_vulnerabilities)
        print("!!! Skip uploading package in testing")
        return

    checksum = inner_upload.upload(package, options.token, options.base_url, options.force, options.changelog)
    scan_report.submit(package, checksum, options.token, options.base_url, options.scan_vulnerabilities)


def publish_directory(directory: str, options: Options):
    check_plugin_daemon_command_exists(options.plugin_daemon_path)

    # delete temp.difypkg if exists
    if os.path.exists("temp.difypkg"):
        os.remove("temp.difypkg")

    # ./dify-plugin-daemon plugin package <directory> --out temp.difypkg
    result = subprocess.run([options.plugin_daemon_path, "plugin", "package", directory, "-o", "temp.difypkg"], capture_output=True, text=True)
    print(result.stdout)
    print(result.stderr)
    if result.returncode != 0:
        raise Exception("Failed to package the directory")

    publish_package("temp.difypkg", options)


def batch_publish_directory(directory: str, options: Options):
    success_dirs = []
    failed_dirs = []
    for dir in os.listdir(directory):
        path = os.path.join(directory, dir)
        print(f"* Uploading directory: {path}")
        try:
            publish_directory(path, options)
            success_dirs.append(path)
        except Exception:
            print(f"** Failed to upload directory: {path}")
            print(traceback.format_exc())
            failed_dirs.append(path)

    if len(failed_dirs) > 0:
        success_dirs_str = "\n ".join(success_dirs)
        failed_dirs_str = "\n ".join(failed_dirs)
        raise Exception(f"!!! Done.\nFailed directories({len(failed_dirs)}):\n {failed_dirs_str}\n\nSuccess directories({len(success_dirs)}):\n {success_dirs_str}")
    else:
        print("!!! Done.")


def check_plugin_daemon_command_exists(plugin_daemon_path: str):
    # ./daemon version
    result = subprocess.run([plugin_daemon_path, "version"], capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        raise Exception("Plugin daemon command not found")
