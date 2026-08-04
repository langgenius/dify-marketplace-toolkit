#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.checks.pr import body
from toolkit.cli import run_check

raise SystemExit(
    run_check(
        body.scan,
        name="PR body",
        description="Check required Marketplace PR body fields.",
        directory=False,
        warnings=False,
        add_args=body.add_args,
        required_paths=(("pr_body_file", "PR body file"),),
    )
)
