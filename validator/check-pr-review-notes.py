import argparse
import re
import sys
from pathlib import Path


HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
HEADING_RE = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)
CHECKBOX_RE = re.compile(r"^[ \t]*-[ \t]*\[(?P<checked>[ xX])\][ \t]*(?P<label>.+?)[ \t]*$", re.MULTILINE)

BREAKING_RE = re.compile(r"\b(breaking|breaks?|backward compatible|no breaking|not breaking)\b", re.IGNORECASE)
HIGH_RISK_BOUNDARY_RE = re.compile(
    r"\b(input constraints?|validated?|allowlist|denylist|security boundary|safety boundary|"
    r"restricted?|limited?|sandbox|dangerous operations?|guardrail)\b",
    re.IGNORECASE,
)


def normalize_heading(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


def strip_template_comments(value: str) -> str:
    return HTML_COMMENT_RE.sub("", value).strip()


def sections(pr_body: str) -> dict[str, str]:
    matches = list(HEADING_RE.finditer(pr_body))
    result: dict[str, str] = {}
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(pr_body)
        result[normalize_heading(match.group(1))] = pr_body[start:end]
    return result


def checked(section: str, label: str) -> bool:
    for match in CHECKBOX_RE.finditer(section):
        if match.group("label").strip().lower() == label.lower():
            return match.group("checked").lower() == "x"
    return False


def validate_review_notes(pr_body: str) -> list[str]:
    parsed = sections(pr_body)
    warnings: list[str] = []

    if checked(parsed.get("submission type", ""), "Version update"):
        change_notes = "\n".join(
            (
                strip_template_comments(parsed.get("what changed", "")),
                strip_template_comments(parsed.get("reviewer notes", "")),
            )
        )
        if not BREAKING_RE.search(change_notes):
            warnings.append(
                "version update PR should state whether there are breaking changes in What changed or Reviewer notes"
            )

    if checked(parsed.get("risk level", ""), "High risk"):
        security_notes = strip_template_comments(parsed.get("security and privacy notes", ""))
        if not HIGH_RISK_BOUNDARY_RE.search(security_notes):
            warnings.append(
                "High risk PR should describe input constraints, security boundaries, or dangerous-operation limits "
                "in Security and privacy notes"
            )

    return warnings


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
    parser = argparse.ArgumentParser(description="Check PR review reminder fields.")
    parser.add_argument("--pr-body-file", required=True, help="Path to a file containing the PR body")
    parser.add_argument("--warning-file", help="Optional file path for review warnings")
    args = parser.parse_args()

    pr_body_path = Path(args.pr_body_file)
    if not pr_body_path.is_file():
        print(f"PR body file not found: {pr_body_path}")
        sys.exit(1)

    pr_body = pr_body_path.read_text(encoding="utf-8", errors="ignore")
    warnings = validate_review_notes(pr_body)
    write_report(args.warning_file, warnings)
    print_report("PR review note warnings:", warnings)
    print("PR review note check passed")


if __name__ == "__main__":
    main()
