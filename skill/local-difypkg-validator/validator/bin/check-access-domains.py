#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.checks import domains
from toolkit.cli import run_check

raise SystemExit(
    run_check(
        domains.scan,
        name="Access domain",
        description="Report and verify plugin access domains.",
        warnings_title="Access domain findings:",
        add_args=domains.add_args,
    )
)
