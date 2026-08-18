#!/usr/bin/env python3
"""Print one section of a Marketplace PR body, for `uploader --with-changelog`.

The extractor never fails a workflow: a missing or empty section prints
nothing and exits 0. Requiring the section is the pre-check's job
(toolkit.checks.pr.body); this tool only carries what review approved.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from toolkit.checks.pr.body import section_content, sections, strip_template_comments


def extract(pr_body: str, section_name: str) -> str:
    content = section_content(sections(pr_body), section_name)
    if content is None:
        return ""
    return strip_template_comments(content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr-body-file", required=True, type=Path)
    parser.add_argument("--section", default="What changed")
    args = parser.parse_args()

    body = args.pr_body_file.read_text(encoding="utf-8", errors="ignore")
    print(extract(body, args.section))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
