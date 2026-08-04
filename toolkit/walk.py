"""Walking a plugin package: which files are worth reading, and which are not.

Every scanner shares this walk, so every exclusion here is load-bearing for all
of them. The two that matter most are pruning vendored dependency trees -- a
package that ships ``Lib/site-packages`` reports its dependencies' hostnames as
its own -- and the per-file size cap, which keeps a single bundled asset from
dominating a scan.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

SCAN_SUFFIXES = {".py", ".yaml", ".yml", ".json", ".toml", ".js", ".ts"}
CODE_SUFFIXES = {".py", ".js", ".ts"}

# Names skipped wherever they appear. Hidden directories are skipped by rule,
# which also covers ``.venv``, ``.venv312``, ``.tox`` and scratch dirs plugins
# occasionally ship.
SKIP_DIR_NAMES = {
    "venv",
    "env",
    "node_modules",
    "vendor",
    "__pycache__",
    "site-packages",
    "dist-packages",
}

# Dependency trees get vendored into packages surprisingly often (a whole
# ``Lib/site-packages`` tree, a ``vendor/*.js`` bundle). Scanning them reports
# the *dependency's* hostnames as the plugin's, which is both wrong and
# unbounded — one package yielded 4657 hosts before this rule existed.
SKIP_PATH_PARTS = {"site-packages", "dist-packages"}

MAX_FILE_BYTES = 1024 * 1024


DEPENDENCY_FILENAMES = {"requirements.txt", "pyproject.toml", "uv.lock"}


def _skip_dir(name: str) -> bool:
    return name.startswith(".") or name.lower() in SKIP_DIR_NAMES


def iter_source_files(root: Path):
    """Yield scannable source files under ``root``, pruning vendored trees."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
        parts = {p.lower() for p in Path(dirpath).parts}
        if parts & SKIP_PATH_PARTS:
            dirnames[:] = []
            continue
        base = Path(dirpath)
        for filename in filenames:
            if filename.startswith("."):
                continue
            path = base / filename
            if path.suffix.lower() not in SCAN_SUFFIXES:
                continue
            if filename in DEPENDENCY_FILENAMES:
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def relative_path(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


def unpack_package(package_path: Path, target_dir: Path) -> None:
    """Extract a ``.difypkg`` (a zip) with zip-slip protection."""
    with zipfile.ZipFile(package_path) as archive:
        for member in archive.infolist():
            member_path = Path(member.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise RuntimeError(f"Unsafe path in package: {member.filename}")
        archive.extractall(target_dir)
