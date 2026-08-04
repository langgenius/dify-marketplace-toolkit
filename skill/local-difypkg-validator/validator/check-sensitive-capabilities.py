"""Check that a PR discloses the sensitive capabilities its plugin uses.

The detection rules live in ``plugin_scan`` so that the uploader reports the
same numbers this gate enforces. Three behaviours changed when they moved
there, all of which used to distort the counts:

* a line is attributed to every category it matches, not only the first in
  declaration order — ``requests.delete(url)`` was previously filed under
  "SQL or database access" and its network signal was lost;
* the per-category limit caps stored samples rather than counting, so a large
  plugin no longer silently reports a truncated total;
* SQL and code-execution rules run against code files only. A YAML parameter
  declared ``type: select`` used to read as a SELECT statement, which put the
  "SQL or database access" hit rate at 67% against a true 5.4%.
"""

import argparse
import re
import sys
from pathlib import Path

from plugin_scan import scan_capabilities


def format_finding(category: str, sample: str) -> str:
    return f"{category}: {sample}"


SENSITIVE_SECTION_RE = re.compile(
    r"^##\s+Security\s+and\s+privacy\s+notes\s*$",
    re.IGNORECASE | re.MULTILINE,
)
NEXT_SECTION_RE = re.compile(r"^##\s+", re.MULTILINE)
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
NONE_NOTES_RE = re.compile(r"^(none|n/a|na|not applicable|no|nothing)\.?$", re.IGNORECASE)




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


def collect_findings(directory: Path) -> list[str]:
    """Flatten the structured scan into the one-finding-per-line report format.

    A category whose sample list was capped still shows its true total, so a
    reviewer can tell "20 call sites" from "20 shown, more not listed".
    """
    findings: list[str] = []
    for category in scan_capabilities(directory):
        for sample in category.samples:
            findings.append(format_finding(category.name, sample))
        hidden = category.count - len(category.samples)
        if hidden > 0:
            findings.append(
                f"{category.name}: {hidden} further match(es) not listed "
                f"({category.count} total)"
            )
    return findings


def validate_sensitive_capabilities(directory: Path, pr_body_path: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    try:
        pr_body = pr_body_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        pr_body = pr_body_path.read_text(encoding="utf-8", errors="ignore")

    notes, section_found = extract_security_notes(pr_body)
    findings = collect_findings(directory)

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
