#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.checks import dependencies
from toolkit.cli import run_check

raise SystemExit(
    run_check(
        dependencies.scan,
        name="Package dependency",
        description="Check plugin dependency policy for Marketplace review.",
    )
)
