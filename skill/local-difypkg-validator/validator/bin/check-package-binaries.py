#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from toolkit.checks import binaries
from toolkit.cli import run_check

raise SystemExit(
    run_check(
        binaries.scan,
        name="Package binaries",
        description="Detect executable or bundled binary files in a package.",
        done="Package binaries check completed",
    )
)
