"""Look up the plugin's pinned dependencies in the OSV vulnerability database.

The existing dependency check enforces pinning hygiene (no ``git+`` installs,
no unconstrained versions). It answers "is this dependency set well-formed",
never "is this dependency set known-vulnerable" — those are different questions
and this script asks the second one.

Reporting is warning-only. A vulnerable transitive dependency is a fact for a
reviewer and a signal for the plugin page; it is not, on its own, grounds for
the pipeline to refuse a submission. ``--fail-on`` exists for when that policy
is decided, and defaults to off.

A database that cannot be reached is reported as such rather than as a clean
result. "No known vulnerabilities" and "we could not check" must never collapse
into the same output.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from osv_client import SEVERITY_ORDER, lookup
from plugin_scan import collect_dependencies


def build_report(directory: Path, offline: bool, fail_on: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    dependencies = collect_dependencies(directory)
    if not dependencies.resolved and not dependencies.unresolved:
        warnings.append("no dependency manifest found; nothing to check")
        return errors, warnings

    warnings.append(
        f"dependency source: {dependencies.source} "
        f"({len(dependencies.resolved)} pinned, {len(dependencies.unresolved)} unpinned)"
    )

    if dependencies.unresolved:
        # An unpinned dependency cannot be looked up: the version that ships is
        # decided at install time. This is the "scan completeness" gap, not a
        # clean result.
        names = ", ".join(item["name"] for item in dependencies.unresolved[:10])
        suffix = "" if len(dependencies.unresolved) <= 10 else ", …"
        warnings.append(
            f"{len(dependencies.unresolved)} dependency(ies) have no exact version and "
            f"were not checked: {names}{suffix}"
        )

    if offline:
        warnings.append("vulnerability lookup skipped (--offline)")
        return errors, warnings

    vulnerabilities, status = lookup(dependencies.resolved)

    if status == "failed":
        warnings.append(
            "vulnerability database unreachable; dependency risk is UNKNOWN for this run"
        )
        return errors, warnings

    if status == "skipped":
        warnings.append("no pinned dependencies to look up")
        return errors, warnings

    if not vulnerabilities:
        warnings.append("no known vulnerabilities in the pinned dependency set")
        return errors, warnings

    threshold = SEVERITY_ORDER.get(fail_on.upper(), 0) if fail_on else 0

    counts: dict[str, int] = {}
    for finding in vulnerabilities:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    summary = ", ".join(
        f"{severity.lower()}: {counts[severity]}"
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        if severity in counts
    )
    warnings.append(f"{len(vulnerabilities)} known vulnerability(ies) — {summary}")

    for finding in vulnerabilities:
        fixed = f"; fixed in {finding['fixed_version']}" if finding["fixed_version"] else ""
        line = (
            f"  [{finding['severity']}] {finding['package']}=={finding['version']} "
            f"{finding['vuln_id']}: {finding['summary'] or 'no summary'}{fixed}"
        )
        if threshold and SEVERITY_ORDER.get(finding["severity"], 0) >= threshold:
            errors.append(line.strip())
        else:
            warnings.append(line)

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
    parser = argparse.ArgumentParser(
        description="Check plugin dependencies against the OSV vulnerability database."
    )
    parser.add_argument("-d", "--directory", required=True, help="The unpacked plugin package directory")
    parser.add_argument("--error-file", help="Optional file path for blocking errors")
    parser.add_argument("--warning-file", help="Optional file path for review warnings")
    parser.add_argument("--offline", action="store_true", help="Collect dependencies without querying OSV")
    parser.add_argument(
        "--fail-on",
        default="",
        choices=["", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Promote findings at or above this severity to blocking errors",
    )
    args = parser.parse_args()

    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Package directory not found: {directory}")
        sys.exit(1)

    errors, warnings = build_report(directory, args.offline, args.fail_on)
    write_report(args.error_file, errors)
    write_report(args.warning_file, warnings)

    print_report("Dependency vulnerability errors:", errors)
    print_report("Dependency vulnerability findings:", warnings)

    if errors:
        sys.exit(1)

    print("Dependency vulnerability check passed")


if __name__ == "__main__":
    main()
