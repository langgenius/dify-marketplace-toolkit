#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.checks import safety
from toolkit.cli import run_check

raise SystemExit(
    run_check(
        safety.scan,
        name="Python safety",
        description="Warn about Python network timeout and credential leak patterns.",
        errors=False,
        done="Python safety warning check passed",
    )
)
