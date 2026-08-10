"""The single CLI shell shared by every check script.

This replaces roughly five hundred lines that were copy-pasted across fourteen
files: the same argparse block, the same two report writers, the same exit-code
rule. Those five hundred lines were the actual maintenance burden -- a third of
every check file was text the reader had already read thirteen times.

The output contract is reproduced exactly, because ``validate-difypkg.py``
parses the report files and both plugin repositories call some of these scripts
directly. A refactor that changes a message is a behaviour change.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Sequence
from pathlib import Path

from toolkit.findings import Findings

Scan = Callable[[argparse.Namespace], Findings]
AddArgs = Callable[[argparse.ArgumentParser], None]


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


def run_check(
    scan: Scan,
    *,
    name: str,
    description: str,
    directory: bool = True,
    errors: bool = True,
    warnings: bool = True,
    warnings_title: str | None = None,
    done: str | None = None,
    add_args: AddArgs | None = None,
    required_paths: Sequence[tuple[str, str]] = (),
) -> int:
    """Turn a ``scan(args) -> Findings`` function into a check CLI.

    ``name`` drives the three default messages -- ``"<name> errors:"``,
    ``"<name> warnings:"`` and ``"<name> check passed"``. Four checks word one
    of those differently and override it rather than bending the default, since
    the strings are part of what reviewers read.

    ``errors=False`` marks a check that has no blocking mode at all: it grows no
    ``--error-file`` flag and can never fail the run. ``warnings=False`` is the
    mirror image. Both are declarations about the check, not about one run.

    ``required_paths`` takes ``(dest, label)`` pairs validated as existing files
    before ``scan`` is called, so every check reports a missing input the same
    way instead of crashing halfway through.

    Returns the process exit code; the caller raises ``SystemExit`` with it.
    """
    parser = argparse.ArgumentParser(description=description)
    if directory:
        parser.add_argument("-d", "--directory", required=True, help="The unpacked plugin package directory")
    if errors:
        parser.add_argument("--error-file", help="Optional file path for blocking errors")
    if warnings:
        parser.add_argument("--warning-file", help="Optional file path for review warnings")
    parser.add_argument("--json", action="store_true", help="Print the result as JSON instead of text")
    if add_args:
        add_args(parser)
    args = parser.parse_args()

    if directory:
        args.directory = Path(args.directory)
        if not args.directory.is_dir():
            print(f"Package directory not found: {args.directory}")
            return 1

    for dest, label in required_paths:
        value = Path(getattr(args, dest))
        setattr(args, dest, value)
        if not value.is_file():
            print(f"{label} not found: {value}")
            return 1

    findings = scan(args)

    if errors:
        write_report(getattr(args, "error_file", None), findings.errors)
    if warnings:
        write_report(getattr(args, "warning_file", None), findings.warnings)

    if args.json:
        print(json.dumps(findings.to_json(), ensure_ascii=False, indent=2))
    else:
        if errors:
            print_report(f"{name} errors:", findings.errors)
        if warnings:
            print_report(warnings_title or f"{name} warnings:", findings.warnings)

    if findings.errors:
        return 1

    if not args.json:
        print(done or f"{name} check passed")
    return 0
