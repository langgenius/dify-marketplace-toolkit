"""Reminders for the two PR shapes where the body usually under-explains itself.

A version update that silently breaks callers, and a self-declared high-risk
plugin that never says what it refuses to do, are both cases where the package
scan sees nothing wrong -- the missing information is the author's intent, and it
only exists in prose. So these are warnings aimed at the reviewer, never blocking
errors: they say "ask about this", not "this is invalid".

Detection is keyword matching over the relevant sections, which is why the
mention itself is enough. ``BREAKING_RE`` accepts "no breaking changes" exactly
as readily as "breaking change" -- the check wants the question answered, and has
no way to judge whether the answer is true.
"""

from __future__ import annotations

import re

from toolkit.findings import Findings

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


def add_args(parser) -> None:
    parser.add_argument("--pr-body-file", required=True, help="Path to a file containing the PR body")


def scan(args) -> Findings:
    pr_body = args.pr_body_file.read_text(encoding="utf-8", errors="ignore")
    return Findings(warnings=validate_review_notes(pr_body))
