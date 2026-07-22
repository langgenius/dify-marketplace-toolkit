import argparse
import re
import sys
from pathlib import Path


HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
CODE_BLOCK_RE = re.compile(r"```.*?```", re.DOTALL)
HEADING_RE = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)
CHECKBOX_RE = re.compile(r"^[ \t]*-[ \t]*\[(?P<checked>[ xX])\][ \t]*(?P<label>.+?)[ \t]*$", re.MULTILINE)
CJK_RE = re.compile(r"[\u3400-\u4DBF\u4E00-\u9FFF]")
ALLOWED_CJK_SNIPPETS = (
    "【中文用户 & Non English User】请使用英语提交，否则会被关闭 ：）",
)

REQUIRED_INFO_FIELDS = (
    "Author",
    "Plugin name",
    "Version",
    "Source repository",
    "Contact",
)

SUBMISSION_TYPES = (
    "New plugin",
    "Version update",
)

RISK_LEVELS = (
    "Low risk",
    "Medium risk",
    "High risk",
)

REQUIRED_TEXT_SECTIONS = (
    "What changed",
    "Local validation",
)

SOURCE_REPOSITORY_RE = re.compile(r"https?://[^\s)>\"]+", re.IGNORECASE)


def strip_template_comments(value: str) -> str:
    return HTML_COMMENT_RE.sub("", value).strip()


def validate_pr_language(pr_body: str) -> list[str]:
    text = CODE_BLOCK_RE.sub("", pr_body)
    text = strip_template_comments(text)
    for snippet in ALLOWED_CJK_SNIPPETS:
        text = text.replace(snippet, "")
    cjk_count = len(CJK_RE.findall(text))
    if cjk_count:
        return [f"PR title/body primary content must be English (found {cjk_count} CJK characters)"]
    return []


def normalize_heading(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


def sections(pr_body: str) -> dict[str, str]:
    matches = list(HEADING_RE.finditer(pr_body))
    result: dict[str, str] = {}

    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(pr_body)
        result[normalize_heading(match.group(1))] = pr_body[start:end]

    return result


def section_content(parsed_sections: dict[str, str], heading: str) -> str | None:
    return parsed_sections.get(normalize_heading(heading))


def checked_options(section: str, expected_labels: tuple[str, ...]) -> list[str]:
    checked: list[str] = []
    expected_by_lower = {label.lower(): label for label in expected_labels}

    for match in CHECKBOX_RE.finditer(section):
        label = match.group("label").strip()
        canonical = expected_by_lower.get(label.lower())
        if canonical and match.group("checked").lower() == "x":
            checked.append(canonical)

    return checked


def field_value(section: str, field_name: str) -> str | None:
    pattern = re.compile(rf"^[ \t]*-[ \t]*\*\*{re.escape(field_name)}\*\*:[ \t]*(.*?)[ \t]*$", re.MULTILINE)
    match = pattern.search(section)
    if not match:
        return None
    return strip_template_comments(match.group(1))


def validate_exactly_one_checkbox(
    parsed_sections: dict[str, str],
    section_name: str,
    labels: tuple[str, ...],
) -> list[str]:
    section = section_content(parsed_sections, section_name)
    if section is None:
        return [f"PR body is missing the '{section_name}' section"]

    checked = checked_options(section, labels)
    if len(checked) != 1:
        return [f"PR '{section_name}' must select exactly one option: {', '.join(labels)}"]

    return []


def validate_plugin_information(parsed_sections: dict[str, str]) -> list[str]:
    errors: list[str] = []
    section = section_content(parsed_sections, "Plugin information")
    if section is None:
        return ["PR body is missing the 'Plugin information' section"]

    for field_name in REQUIRED_INFO_FIELDS:
        value = field_value(section, field_name)
        if value is None:
            errors.append(f"PR 'Plugin information' is missing field: {field_name}")
        elif not value:
            errors.append(f"PR 'Plugin information' field must not be empty: {field_name}")

    source_repository = field_value(section, "Source repository")
    if source_repository and not SOURCE_REPOSITORY_RE.search(source_repository):
        errors.append("PR 'Source repository' must include an http(s) URL")

    return errors


def validate_required_text_sections(parsed_sections: dict[str, str]) -> list[str]:
    errors: list[str] = []

    for section_name in REQUIRED_TEXT_SECTIONS:
        content = section_content(parsed_sections, section_name)
        if content is None:
            errors.append(f"PR body is missing the '{section_name}' section")
            continue
        if not strip_template_comments(content):
            errors.append(f"PR '{section_name}' section must not be empty")

    return errors


def validate_pr_body(pr_body: str) -> list[str]:
    parsed_sections = sections(pr_body)
    errors: list[str] = []

    errors.extend(validate_plugin_information(parsed_sections))
    errors.extend(validate_exactly_one_checkbox(parsed_sections, "Submission type", SUBMISSION_TYPES))
    errors.extend(validate_exactly_one_checkbox(parsed_sections, "Risk level", RISK_LEVELS))
    errors.extend(validate_required_text_sections(parsed_sections))
    errors.extend(validate_pr_language(pr_body))

    return errors


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
    parser = argparse.ArgumentParser(description="Check required Marketplace PR body fields.")
    parser.add_argument("--pr-body-file", required=True, help="Path to a file containing the PR body")
    parser.add_argument("--error-file", help="Optional file path for blocking errors")
    args = parser.parse_args()

    pr_body_path = Path(args.pr_body_file)
    if not pr_body_path.is_file():
        print(f"PR body file not found: {pr_body_path}")
        sys.exit(1)

    try:
        pr_body = pr_body_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        pr_body = pr_body_path.read_text(encoding="utf-8", errors="ignore")

    errors = validate_pr_body(pr_body)
    write_report(args.error_file, errors)
    print_report("PR body errors:", errors)

    if errors:
        sys.exit(1)

    print("PR body check passed")


if __name__ == "__main__":
    main()
