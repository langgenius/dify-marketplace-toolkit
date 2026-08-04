"""README content a first-time user of the plugin needs before installing.

Two things block: a source repository URL, and English prose. The English rule
is enforced by counting CJK characters *outside* fenced code blocks, since
sample payloads and test data legitimately contain them and blocking on those
would push authors to delete useful examples. Localized text is not rejected,
only relocated -- ``README.<locale>.md`` is the naming the Marketplace reads,
and the near-miss forms (``README_zh.md``, ``README-ja.md``) are warned about
rather than silently ignored.

The four section checks are keyword sweeps, so they are warnings: a README can
explain setup without ever using the word "setup". They exist to catch the
README that documents nothing but the plugin's name.
"""

from __future__ import annotations

import re
from pathlib import Path

from toolkit.findings import Findings

SOURCE_REPOSITORY_RE = re.compile(
    r"https?://(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|gitee\.com|codeberg\.org|git\.sr\.ht)/[^\s)>\"]+",
    re.IGNORECASE,
)

REQUIRED_SECTIONS = {
    "setup instructions": (
        "setup",
        "install",
        "installation",
        "configure",
        "configuration",
        "getting started",
    ),
    "usage instructions": (
        "usage",
        "use",
        "example",
        "examples",
        "workflow",
        "chatflow",
    ),
    "required APIs or credentials": (
        "api key",
        "apikey",
        "credential",
        "credentials",
        "token",
        "secret",
        "auth",
        "authentication",
        "authorization",
    ),
    "connection requirements": (
        "connection",
        "connect",
        "endpoint",
        "base url",
        "host",
        "proxy",
        "network",
    ),
}

LOCALIZED_README_RE = re.compile(r"^README[._-][A-Za-z]{2,3}(?:[_-][A-Za-z0-9]+)?\.md$")
EXPECTED_LOCALIZED_README_RE = re.compile(r"^README\.[A-Za-z]{2,3}(?:[_-][A-Za-z0-9]+)?\.md$")
CODE_BLOCK_RE = re.compile(r"```.*?```", re.DOTALL)
CJK_RE = re.compile(r"[\u3400-\u4DBF\u4E00-\u9FFF]")


def read_readme(directory: Path) -> tuple[str | None, list[str]]:
    readme_path = directory / "README.md"
    if not readme_path.is_file():
        return None, ["missing required file: README.md"]
    try:
        content = readme_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        content = readme_path.read_text(encoding="utf-8", errors="ignore")
    if not content.strip():
        return content, ["README.md is empty"]
    return content, []


def validate_localized_readme_paths(directory: Path) -> list[str]:
    warnings: list[str] = []
    for path in directory.glob("README*.md"):
        if path.name == "README.md":
            continue
        if LOCALIZED_README_RE.match(path.name) and not EXPECTED_LOCALIZED_README_RE.match(path.name):
            warnings.append(f"localized README should use README.<locale>.md naming: {path.name}")
    return warnings


def validate_readme(directory: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    content, read_errors = read_readme(directory)
    errors.extend(read_errors)
    if content is None or read_errors:
        return errors, warnings

    if not SOURCE_REPOSITORY_RE.search(content):
        errors.append("README.md must include a source repository URL")

    readable_content = CODE_BLOCK_RE.sub("", content)
    cjk_count = len(CJK_RE.findall(readable_content))
    if cjk_count:
        errors.append(
            "README.md primary content must be English; move localized content to README.<locale>.md "
            f"(found {cjk_count} CJK characters)"
        )

    warnings.extend(validate_localized_readme_paths(directory))

    normalized = content.lower()
    for section_name, keywords in REQUIRED_SECTIONS.items():
        if not any(keyword in normalized for keyword in keywords):
            warnings.append(f"README.md may be missing {section_name}")

    return errors, warnings


def scan(args) -> Findings:
    errors, warnings = validate_readme(args.directory)
    return Findings(errors=errors, warnings=warnings)
