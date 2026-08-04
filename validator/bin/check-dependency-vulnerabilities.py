#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.checks import vulns
from toolkit.cli import run_check

raise SystemExit(
    run_check(
        vulns.scan,
        name="Dependency vulnerability",
        description="Check plugin dependencies against the OSV vulnerability database.",
        warnings_title="Dependency vulnerability findings:",
        add_args=vulns.add_args,
    )
)
