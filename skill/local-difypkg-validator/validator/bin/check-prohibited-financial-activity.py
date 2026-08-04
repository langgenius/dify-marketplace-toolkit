#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.checks import financial
from toolkit.cli import run_check

raise SystemExit(
    run_check(
        financial.scan,
        name="Prohibited financial activity review",
        description="Check for prohibited financial transaction signals.",
        errors=False,
    )
)
