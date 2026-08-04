"""Report the outbound domains a plugin reaches, and compare them to its manifest.

Two jobs:

1. Surface what the static scan found, so an author sees exactly what the
   Marketplace plugin page will show under "Access Domain" before it is public.
2. Cross-check the optional ``network.domains`` node in ``manifest.yaml``. A
   declaration that is never verified is a self-report; verified against the
   scan it becomes evidence, which is what makes the "declared" source worth
   showing next to "detected" at all.

Comparison direction matters and is asymmetric:

* detected but **not** declared -> reported. The author is reaching somewhere
  the manifest does not admit to.
* declared but **not** detected -> fine, silently. Hostnames assembled at
  runtime or held inside an SDK cannot be detected; that gap is precisely what
  a declaration is for.

Defaults to warnings. ``--enforce`` promotes undeclared domains to errors, and
must not be switched on before the submission requirements document tells
authors the field exists — otherwise submissions get blocked by a rule nobody
published.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from plugin_scan import (
    extract_access_domains,
    read_declared_domains,
    undeclared_hosts,
)


def build_report(directory: Path, enforce: bool) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    scan = extract_access_domains(directory)
    declared = read_declared_domains(directory)
    detected = scan.hosts()
    undeclared = undeclared_hosts(detected, declared)

    if detected:
        warnings.append(f"detected {len(detected)} outbound domain(s) by static scan:")
        for domain in scan.domains:
            evidence = ", ".join(domain.sources[:3]) or "no source recorded"
            warnings.append(f"  {domain.host} [{domain.kind}] ({evidence})")

    if scan.runtime_constructed:
        # Without this line the page reads as "this plugin only contacts these
        # hosts", which is false for most plugins: they build the URL at
        # runtime or let an SDK hold it.
        warnings.append(
            f"{scan.runtime_constructed} of {scan.network_callsites} outbound call site(s) "
            "build their address at runtime; those hosts cannot be extracted statically"
        )

    if scan.skipped_data_files:
        warnings.append(
            f"{scan.skipped_data_files} file(s) skipped as data payloads "
            f"(more than the per-file host limit); their URLs are not treated as access domains"
        )

    if scan.truncated:
        warnings.append("host list truncated at the per-package limit")

    if undeclared:
        message = (
            "domains reached by this plugin are missing from manifest.yaml "
            "network.domains: " + ", ".join(undeclared)
        )
        (errors if enforce else warnings).append(message)

    if declared and not detected:
        warnings.append(
            "manifest declares network.domains but the static scan found no literal "
            "hostname; this is expected for SDK-based plugins"
        )

    return errors, warnings


def write_report(path: str | None, lines: list[str]) -> None:
    if not path:
        return
    with open(path, "w", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")


def print_report(title: str, lines: list[str]) -> None:
    if not lines:
        return
    print(title)
    for line in lines:
        print(f"- {line}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Report and verify plugin access domains.")
    parser.add_argument("-d", "--directory", required=True, help="The unpacked plugin package directory")
    parser.add_argument("--error-file", help="Optional file path for blocking errors")
    parser.add_argument("--warning-file", help="Optional file path for review warnings")
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Fail when a detected domain is missing from manifest.yaml network.domains",
    )
    args = parser.parse_args()

    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Package directory not found: {directory}")
        sys.exit(1)

    errors, warnings = build_report(directory, args.enforce)
    write_report(args.error_file, errors)
    write_report(args.warning_file, warnings)

    print_report("Access domain errors:", errors)
    print_report("Access domain findings:", warnings)

    if errors:
        sys.exit(1)

    print("Access domain check passed")


if __name__ == "__main__":
    main()
