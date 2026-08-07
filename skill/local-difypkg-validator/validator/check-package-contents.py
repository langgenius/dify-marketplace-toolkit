#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from toolkit.checks import contents
from toolkit.cli import run_check

raise SystemExit(
    run_check(
        contents.scan,
        name="Package contents",
        description="Check package contents for common development artifacts.",
        add_args=contents.add_args,
    )
)
