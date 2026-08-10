#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from toolkit.checks.pr import review_notes
from toolkit.cli import run_check

raise SystemExit(
    run_check(
        review_notes.scan,
        name="PR review note",
        description="Check PR review reminder fields.",
        directory=False,
        errors=False,
        add_args=review_notes.add_args,
        required_paths=(("pr_body_file", "PR body file"),),
    )
)
