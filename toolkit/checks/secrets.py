"""Credentials accidentally bundled into a package.

Detection runs in two tiers because confidence differs. A vendor-shaped token
-- ``sk-``, ``ghp_``, ``AKIA``, ``xox*``, a JWT, a PEM private-key header -- is
self-identifying, so a match is an error outright. Generic
``password = "..."`` assignments are not: most of them are schema defaults,
config templates, README snippets and ordinary code that *reads* a credential.
The generic tier therefore only blocks when all of these hold:

1. the right-hand side is a literal at all. In code files an unquoted RHS is
   an expression -- ``api_key = credentials.get("api_key")`` is a plugin doing
   its job, not a leak -- so it is skipped outright. In config files
   (``.env``, YAML, ...) bare values are still literals.
2. the value is token-shaped: secret material is drawn from hex or base64-ish
   alphabets and never contains ``(`` or spaces.
3. the value has the entropy of secret material. Thresholds follow
   detect-secrets: 3.0 bits/char for hex, 4.5 for the wider alphabet. This
   trades recall for precision on purpose -- a 24-char random token can land
   below 4.5 -- because near-misses still surface as warnings and the vendor
   tier catches every prefixed format regardless.

Counts and flags (``max_tokens: 4096``) are never secrets and are dropped
before either tier of the generic pass.

Once a line matches a vendor pattern the generic pass is skipped for it,
otherwise the same token reports twice under two names.

Values are always masked. The report files end up in CI logs and PR comments,
so echoing the secret verbatim would republish the thing being reported.

Binaries and files over 1 MiB are skipped rather than scanned: high-entropy
bytes inside a PNG are not a secret, and reading a bundled archive line by line
buys noise at real cost.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
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
    (?P<value>"[^"]*"|'[^']*'|[^"',\s#}]+)
    """
)

# Files where an unquoted right-hand side is code, not a literal value.
CODE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js", ".jsx",
    ".kt", ".m", ".mjs", ".mm", ".php", ".py", ".pyi", ".rb", ".rs",
    ".scala", ".swift", ".ts", ".tsx",
}

# Values that are self-evidently not credentials regardless of their key.
NON_SECRET_VALUES = {"true", "false", "yes", "no", "on", "off"}
NUMERIC_VALUE_RE = re.compile(r"^-?\d+(?:\.\d+)?$")

# Secret material alphabets, with detect-secrets' entropy floors per alphabet.
HEX_VALUE_RE = re.compile(r"^[0-9a-fA-F]+$")
TOKEN_VALUE_RE = re.compile(r"^[A-Za-z0-9+/=_.-]+$")
MIN_HEX_ENTROPY = 3.0
MIN_TOKEN_ENTROPY = 4.5
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


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    total = len(value)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in Counter(value).values()
    )


def looks_like_secret_value(value: str) -> bool:
    """Does this literal have the shape and entropy of secret material?"""
    cleaned = clean_value(value)
    if len(cleaned) < 12:
        return False
    if cleaned.startswith(("http://", "https://")):
        return False
    if cleaned.startswith(("./", "../", "/")):
        return False
    if HEX_VALUE_RE.match(cleaned):
        return shannon_entropy(cleaned) >= MIN_HEX_ENTROPY
    if TOKEN_VALUE_RE.match(cleaned):
        return shannon_entropy(cleaned) >= MIN_TOKEN_ENTROPY
    return False


def mask_secret(value: str) -> str:
    cleaned = clean_value(value)
    if len(cleaned) <= 8:
        return "***"
    return f"{cleaned[:4]}...{cleaned[-4:]}"


def scan_text(rel_path: str, text: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    code_file = Path(rel_path).suffix.lower() in CODE_SUFFIXES

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
            quoted = len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]
            cleaned = clean_value(value)
            if not cleaned or is_placeholder(cleaned):
                continue
            if NUMERIC_VALUE_RE.match(cleaned) or cleaned.lower() in NON_SECRET_VALUES:
                continue
            if code_file and not quoted:
                # An unquoted RHS in code is an expression: reading a
                # credential, not embedding one.
                continue
            if looks_like_secret_value(cleaned):
                errors.append(f"{rel_path}:{line_number} matched secret assignment `{key}`: {mask_secret(cleaned)}")
            else:
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
