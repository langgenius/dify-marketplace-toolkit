#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from toolkit.checks import readme
from toolkit.cli import run_check

raise SystemExit(
    run_check(
        readme.scan,
        name="README metadata",
        description="Check README metadata required by Marketplace review.",
    )
)
