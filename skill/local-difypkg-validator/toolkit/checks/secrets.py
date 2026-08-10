"""Credentials accidentally bundled into a package.

Detection runs in two tiers because confidence differs. A vendor-shaped token
-- ``sk-``, ``ghp_``, ``AKIA``, ``xox*``, a JWT, a PEM private-key header -- is
self-identifying, so a match is an error outright. Generic
``password = "..."`` assignments are not: most of them are schema defaults,
config templates and README snippets. Those go through the value heuristics
below, and a short, templated, URL-shaped or path-shaped value is dropped. The
placeholder list is what keeps that tier usable at all; without it every
``api_key: <YOUR_KEY>`` in the docs would block a release.

Once a line matches a vendor pattern the generic pass is skipped for it,
otherwise the same token reports twice under two names.

Values are always masked. The report files end up in CI logs and PR comments,
so echoing the secret verbatim would republish the thing being reported.

Binaries and files over 1 MiB are skipped rather than scanned: high-entropy
bytes inside a PNG are not a secret, and reading a bundled archive line by line
buys noise at real cost.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from toolkit.findings import Findings

MAX_TEXT_FILE_BYTES = 1024 * 1024
SAMPLE_BYTES = 4096

SKIPPED_DIR_NAMES = {
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
}

BINARY_SUFFIXES = {
    ".7z",
    ".avif",
    ".bmp",
    ".bz2",
    ".dylib",
    ".eot",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".mov",
    ".mp3",
    ".mp4",
    ".otf",
    ".pdf",
    ".png",
    ".rar",
    ".so",
    ".tar",
    ".tgz",
    ".ttf",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
    ".xz",
    ".zip",
}

SECRET_KEYWORDS = (
    "api_key",
    "apikey",
    "access_key",
    "access_token",
    "auth_token",
    "client_secret",
    "password",
    "private_key",
    "secret",
    "token",
)

PLACEHOLDER_VALUES = {
    "",
    "changeme",
    "dummy",
    "example",
    "fake",
    "none",
    "null",
    "placeholder",
    "test",
    "todo",
    "xxx",
    "xxxx",
    "your-api-key",
    "your_api_key",
    "your-key",
    "your-secret",
    "your-token",
}

PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (?P<key>[A-Z0-9_.-]*(?:api[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|private[_-]?key|secret|token)[A-Z0-9_.-]*)
    \s*[:=]\s*
    (?P<value>["']?[^"',\s#}]+["']?)
    """
)
OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")
GITHUB_TOKEN_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


def relative_path(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def is_binary_file(path: Path) -> bool:
    if path.suffix.lower() in BINARY_SUFFIXES:
        return True
    try:
        with path.open("rb") as f:
            return b"\0" in f.read(SAMPLE_BYTES)
    except OSError:
        return True


def clean_value(value: str) -> str:
    return value.strip().strip("\"'")


def is_placeholder(value: str) -> bool:
    normalized = clean_value(value).strip()
    lowered = normalized.lower()
    if lowered in PLACEHOLDER_VALUES:
        return True
    if lowered.startswith("<") and lowered.endswith(">"):
        return True
    if lowered.startswith("${"):
        return True
    if "your" in lowered and any(word in lowered for word in ("key", "secret", "token", "password")):
        return True
    if set(lowered) <= {"x", "*", "-", "_"}:
        return True
    return False


def looks_like_secret_value(value: str) -> bool:
    cleaned = clean_value(value)
    if is_placeholder(cleaned):
        return False
    if len(cleaned) < 12:
        return False
    if cleaned.startswith(("http://", "https://")):
        return False
    if cleaned.startswith(("./", "../", "/")):
        return False
    return True


def mask_secret(value: str) -> str:
    cleaned = clean_value(value)
    if len(cleaned) <= 8:
        return "***"
    return f"{cleaned[:4]}...{cleaned[-4:]}"


def scan_text(rel_path: str, text: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        if PRIVATE_KEY_RE.search(line):
            errors.append(f"{rel_path}:{line_number} matched private key block")

        matched_specific_secret = False
        for pattern_name, pattern in (
            ("OpenAI-style API key", OPENAI_KEY_RE),
            ("GitHub token", GITHUB_TOKEN_RE),
            ("Slack token", SLACK_TOKEN_RE),
            ("AWS access key id", AWS_ACCESS_KEY_RE),
            ("JWT token", JWT_RE),
        ):
            match = pattern.search(line)
            if match:
                matched_specific_secret = True
                errors.append(f"{rel_path}:{line_number} matched {pattern_name}: {mask_secret(match.group(0))}")

        if matched_specific_secret:
            continue

        for match in ASSIGNMENT_RE.finditer(line):
            key = match.group("key")
            value = match.group("value")
            lowered_key = key.lower()
            if not any(keyword in lowered_key for keyword in SECRET_KEYWORDS):
                continue
            if looks_like_secret_value(value):
                errors.append(f"{rel_path}:{line_number} matched secret assignment `{key}`: {mask_secret(value)}")
            elif clean_value(value) and not is_placeholder(value):
                warnings.append(f"{rel_path}:{line_number} review possible secret field `{key}`")

    return errors, warnings


def scan_package(directory: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    for root, dirs, files in os.walk(directory):
        dirs[:] = [dirname for dirname in dirs if dirname not in SKIPPED_DIR_NAMES]
        root_path = Path(root)

        for filename in files:
            file_path = root_path / filename
            rel_path = relative_path(file_path, directory)

            try:
                size = file_path.stat().st_size
            except OSError:
                warnings.append(f"{rel_path} could not be read")
                continue

            if size > MAX_TEXT_FILE_BYTES:
                warnings.append(f"{rel_path} skipped because it is larger than 1 MiB")
                continue

            if is_binary_file(file_path):
                continue

            try:
                text = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                try:
                    text = file_path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    warnings.append(f"{rel_path} could not be decoded")
                    continue
            except OSError:
                warnings.append(f"{rel_path} could not be read")
                continue

            file_errors, file_warnings = scan_text(rel_path, text)
            errors.extend(file_errors)
            warnings.extend(file_warnings)

    return errors, warnings


def scan(args) -> Findings:
    errors, warnings = scan_package(args.directory)
    return Findings(errors=errors, warnings=warnings)
