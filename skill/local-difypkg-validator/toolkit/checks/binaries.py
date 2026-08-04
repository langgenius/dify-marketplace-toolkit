"""Executable and native-binary detection.

Magic bytes are read rather than trusting the suffix, because renaming a file
is the cheapest way to smuggle one past a suffix list. Anything inside a
``.whl`` is downgraded to a warning: wheels legitimately carry compiled
extensions, and blocking them would block most native dependencies.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from toolkit.findings import Findings

MAGIC_BYTES = {
    b"\x7fELF": "ELF executable or shared object",
    b"MZ": "Windows PE executable or DLL",
    b"\xfe\xed\xfa\xce": "Mach-O binary",
    b"\xfe\xed\xfa\xcf": "Mach-O 64-bit binary",
    b"\xce\xfa\xed\xfe": "Mach-O binary",
    b"\xcf\xfa\xed\xfe": "Mach-O 64-bit binary",
    b"\xca\xfe\xba\xbe": "Mach-O universal binary",
    b"\xca\xfe\xba\xbf": "Mach-O universal binary",
}

BINARY_SUFFIXES = {
    ".dll": "Windows dynamic library suffix .dll",
    ".dylib": "macOS dynamic library suffix .dylib",
    ".exe": "Windows executable suffix .exe",
    ".node": "native Node.js addon suffix .node",
    ".pyd": "native Python extension suffix .pyd",
    ".so": "native shared library suffix .so",
}

REVIEW_SUFFIXES = {
    ".app": "application bundle suffix .app",
    ".bin": "binary-like suffix .bin",
    ".command": "macOS command script suffix .command",
    ".run": "installer-like suffix .run",
    ".sh": "shell script suffix .sh",
}

PLATFORM_BINARY_NAME_RE = re.compile(
    r"^(?:dify-plugin-linux-.+|dify-plugin-darwin-.+|dify-plugin-windows-.+\.exe)$",
    re.IGNORECASE,
)

SKIPPED_DIR_NAMES = {
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
}

def relative_path(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def detect_magic(path: Path) -> str | None:
    try:
        with path.open("rb") as f:
            header = f.read(8)
    except OSError:
        return "could not read file header"

    for magic, description in MAGIC_BYTES.items():
        if header.startswith(magic):
            return description
    return None


def first_line(path: Path) -> str:
    try:
        with path.open("rb") as f:
            return f.readline(200).decode("utf-8", errors="ignore").strip()
    except OSError:
        return ""


def has_executable_bit(path: Path) -> bool:
    return os.access(path, os.X_OK)


def is_inside_wheel(path: Path) -> bool:
    return any(part.endswith(".whl") for part in path.parts)


def scan_package(directory: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    seen: set[str] = set()

    def add_report(target: list[str], path: Path, reason: str) -> None:
        rel_path = relative_path(path, directory)
        entry = f"{rel_path}: {reason}"
        if entry not in seen:
            seen.add(entry)
            target.append(entry)

    for root, dirs, files in os.walk(directory):
        dirs[:] = [dirname for dirname in dirs if dirname not in SKIPPED_DIR_NAMES]
        root_path = Path(root)

        for filename in files:
            file_path = root_path / filename
            suffix = file_path.suffix.lower()
            blocks_binary = not is_inside_wheel(file_path)

            if PLATFORM_BINARY_NAME_RE.match(filename):
                add_report(errors, file_path, "platform plugin daemon binary filename is not allowed")

            magic_reason = detect_magic(file_path)
            if magic_reason:
                add_report(errors if blocks_binary else warnings, file_path, magic_reason)

            if suffix in BINARY_SUFFIXES:
                add_report(errors if blocks_binary else warnings, file_path, BINARY_SUFFIXES[suffix])
            elif suffix in REVIEW_SUFFIXES:
                add_report(warnings, file_path, REVIEW_SUFFIXES[suffix])

            if has_executable_bit(file_path):
                line = first_line(file_path)
                if line.startswith("#!"):
                    add_report(warnings, file_path, f"has executable permission with shebang `{line}`")
                else:
                    add_report(warnings, file_path, "has executable permission")

    return errors, warnings


def scan(args) -> Findings:
    errors, warnings = scan_package(args.directory)
    return Findings(errors=errors, warnings=warnings)
