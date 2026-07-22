import argparse
import os
import re
import sys
from pathlib import Path


SCAN_SUFFIXES = {
    ".md",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".py",
    ".js",
    ".ts",
}

SCAN_FILE_NAMES = {
    "README",
    "manifest.yaml",
    "manifest.yml",
}

SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".tox",
    ".nox",
    "node_modules",
}

MAX_FILE_BYTES = 1024 * 1024
MAX_FINDINGS = 100

PATTERNS = {
    "payment processing": (
        r"\bpayment\s+processing\b",
        r"\bprocess(?:ing)?\s+payments?\b",
        r"\bpayments?\b",
        r"\bcheckout\b",
        r"\bcharge(?:s|d)?\b",
        r"\brefund(?:s|ed)?\b",
        r"\bpayout(?:s)?\b",
    ),
    "financial transactions": (
        r"\bfinancial\s+transactions?\b",
        r"\btransactions?\b",
        r"\btrading\b",
        r"\btrade\s+(?:stock|crypto|token|asset)s?\b",
        r"\bplace\s+(?:an?\s+)?orders?\b",
        r"\bbuy\s+(?:stock|crypto|token|asset)s?\b",
        r"\bsell\s+(?:stock|crypto|token|asset)s?\b",
    ),
    "asset transfer": (
        r"\basset\s+transfers?\b",
        r"\btransfer\s+(?:funds?|assets?|money|cash)\b",
        r"\bsend\s+(?:funds?|money|cash)\b",
        r"\bwire\s+transfer\b",
        r"\bwithdraw(?:al|s)?\b",
        r"\bdeposit(?:s)?\b",
    ),
    "token transfer": (
        r"\btoken\s+transfers?\b",
        r"\btransfer\s+(?:crypto|tokens?|coins?|nft)s?\b",
        r"\bsend\s+(?:crypto|tokens?|coins?|nft)s?\b",
        r"\bswap\s+(?:crypto|tokens?|coins?)\b",
        r"\bbridge\s+(?:crypto|tokens?|coins?)\b",
        r"\bwallet\s+transfer\b",
    ),
}

COMPILED_PATTERNS = {
    category: tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)
    for category, patterns in PATTERNS.items()
}


def relative_path(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def should_scan_file(path: Path) -> bool:
    if path.name in SCAN_FILE_NAMES or path.suffix.lower() in SCAN_SUFFIXES:
        try:
            return path.stat().st_size <= MAX_FILE_BYTES
        except OSError:
            return False
    return False


def scan_file(path: Path, base: Path) -> list[str]:
    findings: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        for category, patterns in COMPILED_PATTERNS.items():
            if any(pattern.search(stripped) for pattern in patterns):
                snippet = " ".join(stripped.split())[:180]
                findings.append(f"{category}: {relative_path(path, base)}:{line_number}: {snippet}")
                break

    return findings


def scan_package(directory: Path) -> list[str]:
    findings: list[str] = []

    for root, dirs, files in os.walk(directory):
        dirs[:] = [dirname for dirname in dirs if dirname not in SKIP_DIR_NAMES]
        root_path = Path(root)

        for filename in files:
            path = root_path / filename
            if not should_scan_file(path):
                continue
            findings.extend(scan_file(path, directory))
            if len(findings) >= MAX_FINDINGS:
                findings.append(f"finding limit reached; showing first {MAX_FINDINGS} financial activity findings")
                return findings[: MAX_FINDINGS + 1]

    return findings


def review_warnings(findings: list[str]) -> list[str]:
    if not findings:
        return []
    return [
        "strong manual review required: official Dify Marketplace guidelines prohibit financial transactions, "
        "including payments, asset transfers, and token transfers",
        *findings,
    ]


def write_report(path: str | None, lines: list[str]) -> None:
    if not path:
        return
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def print_report(title: str, lines: list[str]) -> None:
    if not lines:
        return
    print(title)
    for line in lines:
        print(f"- {line}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Check for prohibited financial transaction signals.")
    parser.add_argument("-d", "--directory", required=True, help="The unpacked plugin package directory")
    parser.add_argument("--warning-file", help="Optional file path for strong-review warnings")
    args = parser.parse_args()

    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Package directory not found: {directory}")
        sys.exit(1)

    warnings = review_warnings(scan_package(directory))
    write_report(args.warning_file, warnings)
    print_report("Prohibited financial activity review warnings:", warnings)
    print("Prohibited financial activity review check passed")


if __name__ == "__main__":
    main()
