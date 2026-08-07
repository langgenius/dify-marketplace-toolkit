#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from toolkit.checks import secrets
from toolkit.cli import run_check

raise SystemExit(
    run_check(
        secrets.scan,
        name="Package secrets",
        description="Check package files for accidentally bundled secrets.",
    )
)
