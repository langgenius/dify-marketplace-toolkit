import argparse
import re
import sys
from pathlib import Path


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
    parser = argparse.ArgumentParser(description="Check README metadata required by Marketplace review.")
    parser.add_argument("-d", "--directory", required=True, help="The unpacked plugin package directory")
    parser.add_argument("--error-file", help="Optional file path for blocking errors")
    parser.add_argument("--warning-file", help="Optional file path for review warnings")
    args = parser.parse_args()

    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Package directory not found: {directory}")
        sys.exit(1)

    errors, warnings = validate_readme(directory)
    write_report(args.error_file, errors)
    write_report(args.warning_file, warnings)

    print_report("README metadata errors:", errors)
    print_report("README metadata warnings:", warnings)

    if errors:
        sys.exit(1)

    print("README metadata check passed")


if __name__ == "__main__":
    main()
