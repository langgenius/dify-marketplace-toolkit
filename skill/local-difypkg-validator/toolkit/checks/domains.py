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

from pathlib import Path

from toolkit.findings import Findings
from toolkit.scan.hosts import (
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


def add_args(parser) -> None:
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Fail when a detected domain is missing from manifest.yaml network.domains",
    )


def scan(args) -> Findings:
    errors, warnings = build_report(args.directory, args.enforce)
    return Findings(errors=errors, warnings=warnings)
