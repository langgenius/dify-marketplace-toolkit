"""Development artifacts that should never have been packaged.

A plugin package is built from a working directory, so whatever the author
happened to have on disk ships with it. ``.git`` is the expensive one: it
carries the full history, including the credential someone committed and then
deleted. Caches and virtualenvs are merely dead weight, but the weight is real
-- ``.venv`` pins absolute paths and host-specific binaries that cannot work on
the runtime anyway.

``build`` and ``dist`` are warnings rather than errors because some plugins
legitimately ship generated assets from a directory of that name; the reviewer
decides. ``.env`` is blocked while ``.env.example`` is not, since the example is
documentation and the real file is a leak.

Both size limits are enforced, not just one: the ``.difypkg`` is measured
compressed and the unpacked tree uncompressed, and either alone can pass while
the other blows the ceiling. The file count cap catches a vendored dependency
tree, where no single file looks suspicious.
"""

from __future__ import annotations

import os
from pathlib import Path

from toolkit.findings import Findings

MAX_PACKAGE_BYTES = 50 * 1024 * 1024
MAX_PACKAGE_FILES = 5000

BLOCKED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".tox",
    ".nox",
    ".idea",
    ".vscode",
    "node_modules",
    "pycache",
}

WARNING_DIR_NAMES = {
    "build",
    "dist",
}

BLOCKED_FILE_NAMES = {
    ".DS_Store",
    ".gitconfig",
    "Thumbs.db",
    "desktop.ini",
    "id_rsa",
}

ALLOWED_ENV_FILE_NAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
}

BLOCKED_SUFFIXES = {
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".pyc",
    ".pyo",
    ".log",
    ".tmp",
    ".swp",
    ".swo",
    ".bak",
}

WARNING_SUFFIXES = {
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
}


def relative_path(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def is_blocked_env_file(file_name: str) -> bool:
    if file_name in ALLOWED_ENV_FILE_NAMES:
        return False
    return file_name == ".env" or file_name.startswith(".env.")


def scan_package(directory: Path, package_file: Path | None = None) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    file_count = 0
    total_size = 0

    if package_file is not None:
        try:
            package_size = package_file.stat().st_size
            if package_size > MAX_PACKAGE_BYTES:
                errors.append(f"package file size exceeds 50 MB: {package_size} bytes")
        except OSError:
            errors.append(f"package file could not be read: {package_file}")

    for root, dirs, files in os.walk(directory):
        root_path = Path(root)

        for dirname in list(dirs):
            dir_path = root_path / dirname
            rel_path = relative_path(dir_path, directory)
            if dirname in BLOCKED_DIR_NAMES:
                errors.append(f"blocked directory: {rel_path}/")
                dirs.remove(dirname)
            elif dirname in WARNING_DIR_NAMES:
                warnings.append(f"review directory: {rel_path}/")

        for filename in files:
            file_path = root_path / filename
            rel_path = relative_path(file_path, directory)
            suffix = file_path.suffix.lower()
            file_count += 1
            try:
                total_size += file_path.stat().st_size
            except OSError:
                warnings.append(f"could not stat file: {rel_path}")

            if filename in BLOCKED_FILE_NAMES or is_blocked_env_file(filename):
                errors.append(f"blocked file: {rel_path}")
            elif suffix in BLOCKED_SUFFIXES:
                errors.append(f"blocked file suffix: {rel_path}")
            elif suffix in WARNING_SUFFIXES:
                warnings.append(f"review archive file: {rel_path}")

    if total_size > MAX_PACKAGE_BYTES:
        errors.append(
            f"package contents size exceeds 50 MB: {total_size} bytes"
        )

    if file_count > MAX_PACKAGE_FILES:
        errors.append(f"package contains too many files: {file_count} files")

    return errors, warnings


def add_args(parser) -> None:
    parser.add_argument("--package-file", help="Optional original .difypkg file path for package size checks")


def scan(args) -> Findings:
    package_file = Path(args.package_file) if args.package_file else None
    errors, warnings = scan_package(args.directory, package_file)
    return Findings(errors=errors, warnings=warnings)
