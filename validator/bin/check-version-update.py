#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.checks.pr import version_update
from toolkit.cli import run_check

raise SystemExit(
    run_check(
        version_update.scan,
        name="Version update",
        description="Check version update PR version increment.",
        add_args=version_update.add_args,
        required_paths=(("package_path", "Package file"), ("pr_body_file", "PR body file")),
    )
)
