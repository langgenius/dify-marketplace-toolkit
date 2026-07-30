import argparse
import os
import re
import sys
from pathlib import Path


SENSITIVE_SECTION_RE = re.compile(
    r"^##\s+Security\s+and\s+privacy\s+notes\s*$",
    re.IGNORECASE | re.MULTILINE,
)
NEXT_SECTION_RE = re.compile(r"^##\s+", re.MULTILINE)
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
NONE_NOTES_RE = re.compile(r"^(none|n/a|na|not applicable|no|nothing)\.?$", re.IGNORECASE)

SCAN_SUFFIXES = {
    ".py",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".js",
    ".ts",
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
MAX_MATCHES_PER_CATEGORY = 20

CAPABILITY_PATTERNS = {
    "command execution": (
        r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(",
        r"\bos\.(?:system|popen|spawn[a-z_]*|exec[a-z_]*)\s*\(",
        r"\bpty\.spawn\s*\(",
    ),
    "code execution": (
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bcompile\s*\(",
        r"\bimportlib\.import_module\s*\(",
        r"\b__import__\s*\(",
        r"\bpickle\.loads?\s*\(",
        r"\bmarshal\.loads?\s*\(",
    ),
    "SQL or database access": (
        r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE\s+TABLE)\b",
        r"\b(?:sqlite3|psycopg|psycopg2|pymysql|mysql\.connector|sqlalchemy)\b",
        r"\.execute(?:many)?\s*\(",
    ),
    "SSH or SFTP": (
        r"\b(?:paramiko|fabric|asyncssh|scp|sftp)\b",
        r"\bSSHClient\s*\(",
    ),
    "filesystem operations": (
        r"\bopen\s*\(",
        r"\bPath\s*\(",
        r"\bos\.(?:remove|unlink|rename|replace|makedirs|listdir|walk)\s*\(",
        r"\bshutil\.(?:copy|copyfile|copytree|move|rmtree)\s*\(",
        r"\bglob\.glob\s*\(",
    ),
    "arbitrary network requests": (
        r"\brequests\.(?:get|post|put|patch|delete|request)\s*\(",
        r"\bhttpx\.(?:get|post|put|patch|delete|request)\s*\(",
        r"\baiohttp\.ClientSession\s*\(",
        r"\burllib\.request\.(?:urlopen|Request)\s*\(",
        r"\burlopen\s*\(",
    ),
    "browser automation": (
        r"\b(?:playwright|selenium|pyppeteer|webdriver)\b",
        r"\bbrowser\.new_page\s*\(",
        r"\bpage\.goto\s*\(",
    ),
}

COMPILED_PATTERNS = {
    category: tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)
    for category, patterns in CAPABILITY_PATTERNS.items()
}


def strip_template_comments(value: str) -> str:
    return HTML_COMMENT_RE.sub("", value).strip()


def extract_security_notes(pr_body: str) -> tuple[str | None, bool]:
    match = SENSITIVE_SECTION_RE.search(pr_body)
    if not match:
        return None, False

    start = match.end()
    next_match = NEXT_SECTION_RE.search(pr_body, start)
    end = next_match.start() if next_match else len(pr_body)
    return strip_template_comments(pr_body[start:end]), True


def is_none_notes(notes: str) -> bool:
    normalized = re.sub(r"[\s>*_`-]+", " ", notes).strip()
    return bool(NONE_NOTES_RE.fullmatch(normalized))


def relative_path(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def should_scan_file(path: Path) -> bool:
    if path.suffix.lower() not in SCAN_SUFFIXES:
        return False
    if path.name in {"requirements.txt", "pyproject.toml"}:
        return False
    try:
        return path.stat().st_size <= MAX_FILE_BYTES
    except OSError:
        return False


def scan_capabilities(directory: Path) -> list[str]:
    findings: list[str] = []
    match_counts = {category: 0 for category in COMPILED_PATTERNS}

    for root, dirs, files in os.walk(directory):
        dirs[:] = [dirname for dirname in dirs if dirname not in SKIP_DIR_NAMES]
        root_path = Path(root)

        for filename in files:
            path = root_path / filename
            if not should_scan_file(path):
                continue

            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

            for line_number, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                for category, patterns in COMPILED_PATTERNS.items():
                    if match_counts[category] >= MAX_MATCHES_PER_CATEGORY:
                        continue
                    if any(pattern.search(stripped) for pattern in patterns):
                        snippet = stripped[:180]
                        findings.append(
                            f"{category}: {relative_path(path, directory)}:{line_number}: {snippet}"
                        )
                        match_counts[category] += 1
                        break

    return findings


def validate_sensitive_capabilities(directory: Path, pr_body_path: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    try:
        pr_body = pr_body_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        pr_body = pr_body_path.read_text(encoding="utf-8", errors="ignore")

    notes, section_found = extract_security_notes(pr_body)
    findings = scan_capabilities(directory)

    if not section_found:
        errors.append("PR body is missing the 'Security and privacy notes' section")
    elif notes is None or not notes:
        errors.append("PR 'Security and privacy notes' section must not be empty")
    elif findings and is_none_notes(notes):
        errors.append(
            "PR 'Security and privacy notes' cannot be None/N/A when sensitive capabilities are detected"
        )

    if findings:
        warnings.append("sensitive capability signals detected; reviewer should verify PR disclosure:")
        warnings.extend(findings)

    return errors, warnings


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
    parser = argparse.ArgumentParser(description="Check sensitive capability disclosure in PR body.")
    parser.add_argument("-d", "--directory", required=True, help="The unpacked plugin package directory")
    parser.add_argument("--pr-body-file", required=True, help="Path to a file containing the PR body")
    parser.add_argument("--error-file", help="Optional file path for blocking errors")
    parser.add_argument("--warning-file", help="Optional file path for review warnings")
    args = parser.parse_args()

    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Package directory not found: {directory}")
        sys.exit(1)

    pr_body_path = Path(args.pr_body_file)
    if not pr_body_path.is_file():
        print(f"PR body file not found: {pr_body_path}")
        sys.exit(1)

    errors, warnings = validate_sensitive_capabilities(directory, pr_body_path)
    write_report(args.error_file, errors)
    write_report(args.warning_file, warnings)

    print_report("Sensitive capability disclosure errors:", errors)
    print_report("Sensitive capability disclosure warnings:", warnings)

    if errors:
        sys.exit(1)

    print("Sensitive capability disclosure check passed")


if __name__ == "__main__":
    main()
