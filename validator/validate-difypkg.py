#!/usr/bin/env python3
"""Validate a local Dify .difypkg with Marketplace package checks.

Checks run as subprocesses rather than imports, and that is deliberate. The
input is an arbitrary file uploaded by a stranger: a malformed YAML, a pathological
line length or a catastrophic regex can take a check down. When that happens the
author still needs the other ten results, and a runaway check still needs to be
killable -- neither of which survives an in-process call. The eleven interpreter
starts that buys cost about 160 ms against a run whose slowest step is a network
round trip to the vulnerability database.

What runs, in what order, and when a check may be skipped is declared in
:mod:`toolkit.registry`, not spelled out here.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from shutil import which


@dataclass
class CheckResult:
    name: str
    kind: str
    ok: bool
    errors: list[str]
    warnings: list[str]
    detail: str = ""


def shlex_quote(value: str) -> str:
    if not value:
        return "''"
    safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:=+-")
    if all(char in safe_chars for char in value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def run_cmd(cmd: list[str], *, cwd: Path | None = None, timeout: int | None = None) -> subprocess.CompletedProcess:
    printable = " ".join(shlex_quote(part) for part in cmd)
    print(f"$ {printable}")
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)
    return result


def confirm(prompt: str) -> bool:
    if not sys.stdin.isatty():
        return False
    answer = input(prompt).strip().lower()
    return answer in {"y", "yes"}


def ensure_yq() -> bool:
    if which("yq"):
        return True

    print("Missing required dependency: yq", file=sys.stderr)
    print("The manifest validator uses yq to parse manifest.yaml.", file=sys.stderr)
    if not which("brew"):
        print("Install yq and rerun validation, for example: brew install yq", file=sys.stderr)
        return False

    if not confirm("Install yq with Homebrew now? [y/N] "):
        print("Install yq and rerun validation, for example: brew install yq", file=sys.stderr)
        return False

    result = run_cmd(["brew", "install", "yq"], timeout=600)
    if result.returncode != 0:
        print("Failed to install yq with Homebrew. Install it manually and rerun validation.", file=sys.stderr)
        return False
    return which("yq") is not None


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.rstrip("\n") for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]


def write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def find_toolkit_dir(explicit: str | None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    env_path = os.environ.get("DIFY_MARKETPLACE_TOOLKIT_DIR")
    if env_path:
        candidates.append(Path(env_path).expanduser())

    script_path = Path(__file__).resolve()
    for parent in script_path.parents:
        candidates.append(parent)

    # Probe for what this script actually loads -- the check stubs and the
    # importable core. The old probe required an ``uploader`` directory, which a
    # standalone skill install does not ship, so it walked past the bundled copy
    # and only ever worked from inside a full checkout.
    for candidate in candidates:
        resolved = candidate.resolve()
        if (resolved / "validator" / "bin").is_dir() and (resolved / "toolkit").is_dir():
            return resolved

    raise RuntimeError(
        "Unable to locate dify-marketplace-toolkit. Pass --toolkit-dir or set DIFY_MARKETPLACE_TOOLKIT_DIR."
    )


def run_script_check(
    *,
    check,
    context,
    toolkit_dir: Path,
    unpacked_dir: Path,
    report_dir: Path,
) -> CheckResult:
    script_path = toolkit_dir / "validator" / "bin" / check.script
    error_file = report_dir / f"{check.name}.errors.txt"
    warning_file = report_dir / f"{check.name}.warnings.txt"

    if not script_path.is_file():
        message = f"validator script not found: {script_path}"
        write_lines(error_file, [message])
        return CheckResult(check.name, check.kind, False, [message], [])

    cmd = [sys.executable, str(script_path), "-d", str(unpacked_dir), *check.args(context)]
    if check.blocking:
        cmd.extend(["--error-file", str(error_file), "--warning-file", str(warning_file)])
    else:
        cmd.extend(["--warning-file", str(warning_file)])

    result = run_cmd(cmd, timeout=300)
    errors = read_lines(error_file)
    warnings = read_lines(warning_file)

    # A check that dies without writing its report still has to surface. Without
    # this the run would read as "no findings" for a check that never ran.
    if result.returncode != 0 and (not check.blocking or not errors):
        errors = [f"{check.script} failed with exit code {result.returncode}"]
        if result.stderr.strip():
            errors.append(result.stderr.strip())
        elif check.blocking and result.stdout.strip():
            errors.append(result.stdout.strip())
        write_lines(error_file, errors)

    return CheckResult(
        name=check.name,
        kind=check.kind,
        ok=not errors,
        errors=errors,
        warnings=warnings,
    )


def run_compile_check(check, unpacked_dir: Path, report_dir: Path) -> CheckResult:
    error_file = report_dir / f"{check.name}.errors.txt"
    result = run_cmd([sys.executable, "-m", "compileall", "-q", str(unpacked_dir)], timeout=300)
    errors: list[str] = []
    if result.returncode != 0:
        errors.append(f"python compileall failed with exit code {result.returncode}")
        if result.stdout.strip():
            errors.append(result.stdout.strip())
        if result.stderr.strip():
            errors.append(result.stderr.strip())
    write_lines(error_file, errors)
    return CheckResult(check.name, check.kind, not errors, errors, [])


def markdown_table_cell(text: str, limit: int = 180) -> str:
    normalized = " ".join(text.replace("\r", "\n").split())
    if len(normalized) > limit:
        normalized = normalized[: limit - 1].rstrip() + "…"
    return normalized.replace("|", "\\|")


def build_summary_lines(results: list[CheckResult], report_dir: Path, skipped: list[str]) -> list[str]:
    blocking_failures = [result for result in results if result.kind == "blocking" and result.errors]
    warning_results = [result for result in results if result.warnings]
    env_failures = [result for result in results if result.kind == "warning" and result.errors]

    lines = [
        "## Local DIFYPKG Validation Summary",
        "",
        f"- Report directory: {report_dir}",
        f"- Blocking failures: {len(blocking_failures)}",
        f"- Warning categories: {len(warning_results)}",
        f"- Environment/check execution failures: {len(env_failures)}",
        "",
        "| Check | Type | Status | Findings |",
        "|---|---|---|---|",
    ]

    for result in results:
        status = "PASS" if result.ok else "FAIL"
        first_findings = result.errors or result.warnings
        detail = markdown_table_cell(first_findings[0] if first_findings else result.detail or "No findings.")
        lines.append(f"| `{result.name}` | {result.kind} | {status} | {detail} |")

    if skipped:
        lines.extend(["", "### Skipped checks"])
        for item in skipped:
            lines.append(f"- {item}")

    if blocking_failures:
        lines.extend(["", "### Blocking failures"])
        for result in blocking_failures:
            lines.append(f"- {result.name}:")
            for item in result.errors[:10]:
                lines.append(f"  - {item}")
            if len(result.errors) > 10:
                lines.append(f"  - ... {len(result.errors) - 10} more")

    if warning_results:
        lines.extend(["", "### Warnings for review"])
        for result in warning_results:
            lines.append(f"- {result.name}:")
            for item in result.warnings[:10]:
                lines.append(f"  - {item}")
            if len(result.warnings) > 10:
                lines.append(f"  - ... {len(result.warnings) - 10} more")

    return lines


def print_summary(results: list[CheckResult], report_dir: Path, skipped: list[str]) -> None:
    lines = build_summary_lines(results, report_dir, skipped)
    summary_path = report_dir / "summary.md"
    write_lines(summary_path, lines)
    print("\n" + "\n".join(lines))
    print(f"\nSummary report written to: {summary_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a local .difypkg with Marketplace package validators."
    )
    parser.add_argument("package", help="Path to the local .difypkg package")
    parser.add_argument("--toolkit-dir", help="Path to dify-marketplace-toolkit checkout")
    parser.add_argument("--output-dir", help="Directory where reports should be written")
    parser.add_argument("--pr-body-file", help="Optional PR body file for sensitive capability disclosure checks")
    parser.add_argument("--keep-temp", action="store_true", help="Keep unpacked package temp directory")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip checks that query external services (dependency vulnerability lookup)",
    )
    args = parser.parse_args()

    package_path = Path(args.package).expanduser().resolve()
    if not package_path.is_file():
        print(f"ERROR: package file not found: {package_path}", file=sys.stderr)
        return 1
    if package_path.suffix != ".difypkg":
        print(f"ERROR: expected a .difypkg file: {package_path}", file=sys.stderr)
        return 1

    if not ensure_yq():
        return 1

    try:
        toolkit_dir = find_toolkit_dir(args.toolkit_dir)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # Import after the checkout is located so a --toolkit-dir pointing at another
    # checkout gets that checkout's registry, not this one's.
    sys.path.insert(0, str(toolkit_dir))
    from toolkit.registry import CHECKS, COMPILE, OUT_OF_SCOPE, Context
    from toolkit.walk import unpack_package

    context = Context(
        package_path=package_path,
        pr_body_file=Path(args.pr_body_file).expanduser().resolve() if args.pr_body_file else None,
        offline=args.offline,
    )

    temp_obj = tempfile.TemporaryDirectory(prefix="local-difypkg-validator-")
    temp_root = Path(temp_obj.name)
    unpacked_dir = temp_root / "unpacked_plugin"
    report_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else temp_root / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    results: list[CheckResult] = []
    skipped: list[str] = []

    try:
        unpacked_dir.mkdir(parents=True, exist_ok=True)
        try:
            unpack_package(package_path, unpacked_dir)
        except Exception as exc:
            result = CheckResult("safe_unzip", "blocking", False, [str(exc)], [])
            write_lines(report_dir / "safe_unzip.errors.txt", result.errors)
            results.append(result)
            print_summary([result], report_dir, skipped)
            return 1

        for check in CHECKS:
            if not check.available(context):
                if check.skip_reason:
                    skipped.append(check.skip_reason)
                continue
            if check.runner == COMPILE:
                results.append(run_compile_check(check, unpacked_dir, report_dir))
            else:
                results.append(
                    run_script_check(
                        check=check,
                        context=context,
                        toolkit_dir=toolkit_dir,
                        unpacked_dir=unpacked_dir,
                        report_dir=report_dir,
                    )
                )

        skipped.extend(OUT_OF_SCOPE)
        print_summary(results, report_dir, skipped)

        return 1 if any(result.errors for result in results) else 0
    finally:
        if args.keep_temp:
            print(f"\nTemp directory kept at: {temp_root}")
        else:
            temp_obj.cleanup()


if __name__ == "__main__":
    sys.exit(main())
