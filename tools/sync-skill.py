#!/usr/bin/env python3
"""Regenerate the bundled skill copy, or fail if it has drifted.

``skill/local-difypkg-validator/`` ships its own copy of the validator so the
skill works without a toolkit checkout. That copy used to be maintained by hand,
which meant every new file had to be written twice and the two trees stayed in
sync only as long as nobody forgot. They are the same bytes by definition, so a
script should own them.

``--check`` is the CI half: it reports drift and exits non-zero without touching
anything, so a pull request that edits one tree and not the other fails before
merge rather than shipping a stale skill.
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = REPO_ROOT / "skill" / "local-difypkg-validator"

sys.path.insert(0, str(REPO_ROOT))

from toolkit.registry import CHECKS  # noqa: E402

# What the skill needs to run `validate-difypkg.py` standalone. The uploader is
# deliberately absent: the skill validates a package, it never publishes one.
# The check stubs come from the registry, so a new check cannot be forgotten
# here — the same table that runs it also ships it.
MIRRORED_TREES = ("toolkit",)
MIRRORED_FILES = (
    "validator/validate-difypkg.py",
    *sorted({f"validator/{check.script}" for check in CHECKS if check.script}),
)

IGNORED = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")


def mirrored_paths() -> list[Path]:
    """Every repo-relative path the skill copy is expected to contain."""
    paths: list[Path] = []
    for tree in MIRRORED_TREES:
        root = REPO_ROOT / tree
        for path in sorted(root.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"}:
                paths.append(path.relative_to(REPO_ROOT))
    paths.extend(Path(name) for name in MIRRORED_FILES)
    return paths


def sync() -> int:
    for tree in MIRRORED_TREES:
        target = SKILL_ROOT / tree
        if target.exists():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(REPO_ROOT / tree, target, ignore=IGNORED)
    for name in MIRRORED_FILES:
        target = SKILL_ROOT / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / name, target)

    # Anything the skill still carries from before a rename or a layout move
    # is now unreachable and would only confuse the next reader.
    mirrored = {SKILL_ROOT / name for name in MIRRORED_FILES}
    for stale in sorted((SKILL_ROOT / "validator").rglob("*")):
        if stale.is_file() and stale not in mirrored:
            stale.unlink()
            print(f"removed stale {stale.relative_to(REPO_ROOT)}")
    for leftover in sorted((SKILL_ROOT / "validator").rglob("*"), reverse=True):
        if leftover.is_dir() and not any(leftover.iterdir()):
            leftover.rmdir()

    print(f"synced {len(mirrored_paths())} file(s) into {SKILL_ROOT.relative_to(REPO_ROOT)}")
    return 0


def check() -> int:
    drifted: list[str] = []
    for relative in mirrored_paths():
        source = REPO_ROOT / relative
        target = SKILL_ROOT / relative
        if not target.is_file():
            drifted.append(f"missing in skill: {relative}")
        elif not filecmp.cmp(source, target, shallow=False):
            drifted.append(f"differs from source: {relative}")

    expected = {SKILL_ROOT / relative for relative in mirrored_paths()}
    for tree in (*MIRRORED_TREES, "validator"):
        root = SKILL_ROOT / tree
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path not in expected:
                drifted.append(f"not in source: {path.relative_to(SKILL_ROOT)}")

    if drifted:
        print("Skill copy is out of sync with the repository:", file=sys.stderr)
        for item in drifted:
            print(f"  - {item}", file=sys.stderr)
        print("\nRun: python3 tools/sync-skill.py", file=sys.stderr)
        return 1

    print(f"skill copy matches the repository ({len(expected)} file(s))")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="Report drift and exit non-zero instead of copying")
    args = parser.parse_args()
    return check() if args.check else sync()


if __name__ == "__main__":
    sys.exit(main())
