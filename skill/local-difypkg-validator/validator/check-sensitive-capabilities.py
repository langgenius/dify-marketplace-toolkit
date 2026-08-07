#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from toolkit.checks import sensitive
from toolkit.cli import run_check

raise SystemExit(
    run_check(
        sensitive.scan,
        name="Sensitive capability disclosure",
        description="Check sensitive capability disclosure in PR body.",
        add_args=sensitive.add_args,
        required_paths=(("pr_body_file", "PR body file"),),
    )
)
