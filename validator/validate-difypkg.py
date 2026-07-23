#!/usr/bin/env python3
"""Validate a local Dify .difypkg with Marketplace package checks."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import zipfile
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

    for candidate in candidates:
        resolved = candidate.resolve()
        if (resolved / "validator").is_dir() and (resolved / "uploader").is_dir():
            return resolved

    raise RuntimeError(
        "Unable to locate dify-marketplace-toolkit. Pass --toolkit-dir or set DIFY_MARKETPLACE_TOOLKIT_DIR."
    )


def safe_unzip(package_path: Path, target_dir: Path) -> None:
    with zipfile.ZipFile(package_path) as archive:
        for member in archive.infolist():
            member_path = Path(member.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise RuntimeError(f"Unsafe path in package: {member.filename}")
        archive.extractall(target_dir)


def run_validator(
    *,
    name: str,
    toolkit_dir: Path,
    script_name: str,
    unpacked_dir: Path,
    report_dir: Path,
    blocking: bool,
    extra_args: list[str] | None = None,
) -> CheckResult:
    script_path = toolkit_dir / "validator" / script_name
    error_file = report_dir / f"{name}.errors.txt"
    warning_file = report_dir / f"{name}.warnings.txt"

    if not script_path.is_file():
        message = f"validator script not found: {script_path}"
        write_lines(error_file, [message])
        return CheckResult(name, "blocking" if blocking else "warning", False, [message], [])

    cmd = [
        sys.executable,
        str(script_path),
        "-d",
        str(unpacked_dir),
    ]
    if extra_args:
        cmd.extend(extra_args)

    if blocking:
        cmd.extend(["--error-file", str(error_file), "--warning-file", str(warning_file)])
    else:
        cmd.extend(["--warning-file", str(warning_file)])

    result = run_cmd(cmd, timeout=300)
    errors = read_lines(error_file)
    warnings = read_lines(warning_file)
    if blocking and result.returncode != 0 and not errors:
        errors = [f"{script_name} failed with exit code {result.returncode}"]
        if result.stderr.strip():
            errors.append(result.stderr.strip())
        elif result.stdout.strip():
            errors.append(result.stdout.strip())
        write_lines(error_file, errors)
    if not blocking and result.returncode != 0:
        errors = [f"{script_name} failed with exit code {result.returncode}"]
        if result.stderr.strip():
            errors.append(result.stderr.strip())
        write_lines(error_file, errors)

    return CheckResult(
        name=name,
        kind="blocking" if blocking else "warning",
        ok=not errors,
        errors=errors,
        warnings=warnings,
    )


def run_compile_check(unpacked_dir: Path, report_dir: Path) -> CheckResult:
    error_file = report_dir / "python_compile.errors.txt"
    result = run_cmd([sys.executable, "-m", "compileall", "-q", str(unpacked_dir)], timeout=300)
    errors: list[str] = []
    if result.returncode != 0:
        errors.append(f"python compileall failed with exit code {result.returncode}")
        if result.stdout.strip():
            errors.append(result.stdout.strip())
        if result.stderr.strip():
            errors.append(result.stderr.strip())
    write_lines(error_file, errors)
    return CheckResult("python_compile", "blocking", not errors, errors, [])


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
    print()
    print("\n".join(lines))
    print(f"\nSummary report written to: {summary_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a local Dify .difypkg with Marketplace package validators."
    )
    parser.add_argument("package", help="Path to the local .difypkg package")
    parser.add_argument("--toolkit-dir", help="Path to dify-marketplace-toolkit checkout")
    parser.add_argument("--output-dir", help="Directory where reports should be written")
    parser.add_argument("--pr-body-file", help="Optional PR body file for sensitive capability disclosure checks")
    parser.add_argument("--keep-temp", action="store_true", help="Keep unpacked package temp directory")
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
            safe_unzip(package_path, unpacked_dir)
        except Exception as exc:
            result = CheckResult("safe_unzip", "blocking", False, [str(exc)], [])
            write_lines(report_dir / "safe_unzip.errors.txt", result.errors)
            results.append(result)
            print_summary(results, report_dir, skipped)
            return 1

        blocking_validators = [
            ("package_contents", "check-package-contents.py", ["--package-file", str(package_path)]),
            ("package_secrets", "check-package-secrets.py", []),
            ("package_binaries", "check-package-binaries.py", []),
            ("manifest_metadata", "check-manifest-metadata.py", []),
            ("readme_metadata", "check-readme-metadata.py", []),
            ("package_dependencies", "check-package-dependencies.py", []),
        ]

        for name, script_name, extra_args in blocking_validators:
            results.append(
                run_validator(
                    name=name,
                    toolkit_dir=toolkit_dir,
                    script_name=script_name,
                    unpacked_dir=unpacked_dir,
                    report_dir=report_dir,
                    blocking=True,
                    extra_args=extra_args,
                )
            )

        results.append(run_compile_check(unpacked_dir, report_dir))

        warning_validators = [
            ("python_safety", "check-python-safety-warnings.py"),
            ("prohibited_financial_activity", "check-prohibited-financial-activity.py"),
        ]
        for name, script_name in warning_validators:
            results.append(
                run_validator(
                    name=name,
                    toolkit_dir=toolkit_dir,
                    script_name=script_name,
                    unpacked_dir=unpacked_dir,
                    report_dir=report_dir,
                    blocking=False,
                )
            )

        if args.pr_body_file:
            pr_body_file = Path(args.pr_body_file).expanduser().resolve()
            results.append(
                run_validator(
                    name="sensitive_capabilities",
                    toolkit_dir=toolkit_dir,
                    script_name="check-sensitive-capabilities.py",
                    unpacked_dir=unpacked_dir,
                    report_dir=report_dir,
                    blocking=True,
                    extra_args=["--pr-body-file", str(pr_body_file)],
                )
            )
        else:
            skipped.append("sensitive capability disclosure blocking check requires --pr-body-file")

        skipped.extend(
            [
                "PR title/body language and template checks require GitHub PR metadata",
                "Marketplace duplicate-version check requires Marketplace/PR workflow context",
                "plugin install and upload-package tests are not run by this local validator",
            ]
        )

        print_summary(results, report_dir, skipped)

        has_errors = any(result.errors for result in results)
        return 1 if has_errors else 0
    finally:
        if args.keep_temp:
            print(f"\nTemp directory kept at: {temp_root}")
        else:
            temp_obj.cleanup()


if __name__ == "__main__":
    sys.exit(main())
