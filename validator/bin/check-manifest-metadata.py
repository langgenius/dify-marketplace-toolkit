#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.checks import manifest
from toolkit.cli import run_check

raise SystemExit(
    run_check(
        manifest.scan,
        name="Manifest metadata",
        description="Check plugin manifest metadata required by Marketplace review.",
    )
)
