import argparse
import os
import sys
from pathlib import Path


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


def write_report(path: str | None, lines: list[str]) -> None:
    if not path:
        return
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def print_report(title: str, lines: list[str]) -> None:
    if not lines:
        return
    print(title)
    for line in lines:
        print(f"- {line}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Check package contents for common development artifacts.")
    parser.add_argument("-d", "--directory", required=True, help="The unpacked plugin package directory")
    parser.add_argument("--package-file", help="Optional original .difypkg file path for package size checks")
    parser.add_argument("--error-file", help="Optional file path for blocking errors")
    parser.add_argument("--warning-file", help="Optional file path for review warnings")
    args = parser.parse_args()

    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Package directory not found: {directory}")
        sys.exit(1)

    package_file = Path(args.package_file) if args.package_file else None
    errors, warnings = scan_package(directory, package_file)
    write_report(args.error_file, errors)
    write_report(args.warning_file, warnings)

    print_report("Package contents errors:", errors)
    print_report("Package contents warnings:", warnings)

    if errors:
        sys.exit(1)

    print("Package contents check passed")


if __name__ == "__main__":
    main()
