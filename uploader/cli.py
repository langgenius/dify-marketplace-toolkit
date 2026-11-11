"""Command line surface for publishing plugins to the Marketplace.

Publishing takes two calls. The upload happens first and alone decides
success (``package_upload``); the packaged artifact is then scanned and the
report is submitted against the checksum the upload response assigned to it
(``scan_report``). A report that fails to build or to arrive only costs the
plugin page its scan data until a rescan. **Publishing a plugin must never
fail because a scanner did.**

A publish may also fan out to *mirrors* (``--mirror-url`` / ``--mirror-token``)
so a merged plugin lands on staging as well as production. Three rules keep a
mirror from ever holding production back:

* the primary target is uploaded first and is the only one whose failure is
  raised — a mirror failure degrades to a ``::warning::``, exactly like the
  scan report;
* the scan is built **once** and reused, because it describes the local
  package bytes and not the target; and
* each target's report is submitted against *its own* checksum, because every
  deployment re-signs the artifact with its own key and therefore assigns it a
  different checksum.

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

from uploader import package_upload, scan_report


@dataclasses.dataclass(frozen=True)
class Target:
    """One Marketplace deployment to publish into."""

    base_url: str
    token: str


@dataclasses.dataclass
class Options:
    token: str
    base_url: str
    force: bool
    changelog: str
    testing: bool
    scan_vulnerabilities: bool
    plugin_daemon_path: str
    mirrors: tuple[Target, ...] = ()
    allow_category_change: bool = False


def main():
    parser = argparse.ArgumentParser(description="Upload a package or directory to the marketplace. Choose one of the following sources: -p(--package), -d(--directory), --batch-directory")
    # -p, --package
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--package", type=str, help="The package to upload")
    group.add_argument("-d", "--directory", type=str, help="The directory to package and upload")
    group.add_argument("--batch-directory", type=str, help="Batch upload all directories in the given directory")
    parser.add_argument("-t", "--token", type=str, help="The token to use for authentication; not needed with --test, which never talks to the Marketplace")
    parser.add_argument("-u", "--base-url", type=str, help="The base url to use for the request")
    parser.add_argument("-f", "--force", action="store_true", help="Force upload the package, ignore version check")
    parser.add_argument(
        "--allow-category-change",
        action="store_true",
        help="Let this version move the plugin to another category (the Marketplace still refuses moves to or from trigger)",
    )
    parser.add_argument("--with-changelog", action="store_true", help="Whether to read changelog from stdin")
    parser.add_argument("--plugin-daemon-path", type=str, help="The path to the plugin daemon")
    parser.add_argument("--test", action="store_true", help="Indicates that this is a testing")
    parser.add_argument(
        "--no-vuln-scan",
        action="store_true",
        help="Collect dependencies but do not query the vulnerability database",
    )
    parser.add_argument(
        "--mirror-url",
        action="append",
        default=[],
        metavar="URL",
        help="Additional Marketplace to publish into, repeatable. Pairs positionally with "
             "--mirror-token. An empty value is dropped, so an unset CI secret means "
             "'no mirror' instead of a broken command line. A mirror never fails the publish.",
    )
    parser.add_argument(
        "--mirror-token",
        action="append",
        default=[],
        metavar="TOKEN",
        help="Auth token for the --mirror-url at the same position",
    )
    args = parser.parse_args()

    if not args.test and not args.token:
        parser.error("-t/--token is required unless --test is given")

    # if --with-changelog == true, read changelog from stdin
    if args.with_changelog:
        changelog = sys.stdin.read()
        args.changelog = changelog.strip()
    else:
        args.changelog = ""

    print(json.dumps(args.__dict__, indent=2))

    options = Options(
        token=args.token or "",
        base_url=args.base_url or "",
        force=args.force,
        changelog=args.changelog,
        testing=args.test,
        scan_vulnerabilities=not args.no_vuln_scan,
        plugin_daemon_path=args.plugin_daemon_path or "./dify-plugin",
        mirrors=parse_mirrors(parser, args.mirror_url, args.mirror_token),
        allow_category_change=args.allow_category_change,
    )

    if args.package:
        publish_package(args.package, options)
    elif args.directory:
        publish_directory(args.directory, options)
    elif args.batch_directory:
        batch_publish_directory(args.batch_directory, options)
    else:
        print("No package or directory provided")


def parse_mirrors(parser, urls, tokens) -> tuple[Target, ...]:
    """Pair ``--mirror-url`` with ``--mirror-token`` positionally.

    A blank URL drops its whole pair: workflows pass
    ``--mirror-url ${{ secrets.MARKETPLACE_STAGING_BASE_URL }}`` unconditionally,
    and an unset secret expands to the empty string. Silently meaning "no
    mirror" there is what lets the workflow change land before the secret
    exists. A URL with no token is the opposite — a misconfiguration that would
    otherwise surface as a 401 per plugin — so it stops the command line.
    """
    if len(urls) != len(tokens):
        parser.error(
            f"--mirror-url given {len(urls)} time(s) but --mirror-token {len(tokens)} time(s); "
            "they pair positionally"
        )

    mirrors = []
    for url, token in zip(urls, tokens):
        url, token = url.strip(), token.strip()
        if not url:
            continue
        if not token:
            parser.error(f"--mirror-url {url} has no --mirror-token")
        mirrors.append(Target(base_url=url.rstrip("/"), token=token))
    return tuple(mirrors)


def publish_package(package: str, options: Options):
    if options.testing:
        # A pre-check run is where an author first sees what the plugin page
        # will say, so the scan still runs — there is just nothing published
        # and therefore no checksum to submit a report against.
        scan_report.build(package, options.scan_vulnerabilities)
        print("!!! Skip uploading package in testing")
        return

    # The primary target decides the exit code; it goes first so a package that
    # production rejects never reaches a mirror either.
    checksum = package_upload.upload(
        package, options.token, options.base_url, options.force, options.changelog, options.allow_category_change
    )

    # Built once: the report describes the package bytes, which are the same
    # everywhere, and building it means resolving dependencies and querying
    # OSV/PyPI. Submitting it is per-target, against that target's checksum.
    report = scan_report.build(package, options.scan_vulnerabilities)
    if report is None:
        scan_report.warn("security scan failed; scan report not submitted")
    scan_report.post(report, checksum, options.token, options.base_url)

    for mirror in options.mirrors:
        publish_to_mirror(package, report, mirror, options)


def publish_to_mirror(package: str, report, mirror: Target, options: Options):
    """Publish into a secondary deployment, absorbing every failure.

    A mirror is a test environment, not the record of truth. Its upload is
    forced regardless of ``--force``: the question a mirror answers is "did the
    pipeline reach it", and a 409 from a version some backfill already put there
    would hide the answer rather than report it.
    """
    try:
        checksum = package_upload.upload(
            package, mirror.token, mirror.base_url, True, options.changelog, options.allow_category_change
        )
    except Exception:
        scan_report.warn(f"mirror publish to {mirror.base_url} failed; the primary publish is unaffected")
        print(traceback.format_exc())
        return
    print(f"Mirrored to {mirror.base_url}")
    scan_report.post(report, checksum, mirror.token, mirror.base_url)


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
