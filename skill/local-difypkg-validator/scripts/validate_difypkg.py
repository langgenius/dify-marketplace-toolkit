#!/usr/bin/env python3
"""Skill wrapper for the generic validator/validate-difypkg.py CLI."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def toolkit_from_args(args: list[str]) -> Path | None:
    for index, arg in enumerate(args):
        if arg == "--toolkit-dir" and index + 1 < len(args):
            return Path(args[index + 1]).expanduser().resolve()
        if arg.startswith("--toolkit-dir="):
            return Path(arg.split("=", 1)[1]).expanduser().resolve()
    return None


def find_cli(args: list[str]) -> Path:
    explicit_toolkit = toolkit_from_args(args)
    candidates: list[Path] = []
    if explicit_toolkit:
        candidates.append(explicit_toolkit)
    env_toolkit = os.environ.get("DIFY_MARKETPLACE_TOOLKIT_DIR")
    if env_toolkit:
        candidates.append(Path(env_toolkit).expanduser())

    script_path = Path(__file__).resolve()
    candidates.extend(script_path.parents)

    for candidate in candidates:
        resolved = candidate.resolve()
        cli_path = resolved / "validator" / "validate-difypkg.py"
        if cli_path.is_file():
            return cli_path

    raise RuntimeError(
        "Unable to locate bundled validator/validate-difypkg.py. "
        "Reinstall the complete local-difypkg-validator skill, or pass --toolkit-dir."
    )


def main() -> int:
    args = sys.argv[1:]
    try:
        cli_path = find_cli(args)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    result = subprocess.run([sys.executable, str(cli_path), *args])
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
