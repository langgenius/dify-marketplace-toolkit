"""The dependency set a plugin ships, resolved as exactly as its files allow.

Preference runs from most to least exact: ``uv.lock`` is a full transitive
closure, ``requirements.txt`` is usually pinned, ``pyproject.toml`` is mostly
ranges. What cannot be pinned is kept in ``unresolved`` rather than dropped,
because "we could not check this one" is a different answer from "this one is
clean" and the vulnerability lookup must not blur them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from toolkit.walk import read_text

REQUIREMENT_PIN_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#,]+)"
)
REQUIREMENT_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
UV_LOCK_NAME_RE = re.compile(r'^\s*name\s*=\s*"([^"]+)"')
UV_LOCK_VERSION_RE = re.compile(r'^\s*version\s*=\s*"([^"]+)"')


def normalise_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


@dataclass
class DependencyScan:
    source: str = ""
    resolved: list[dict] = field(default_factory=list)
    unresolved: list[dict] = field(default_factory=list)

    def to_json(self) -> dict:
        return {
            "source": self.source,
            "resolved": self.resolved,
            "unresolved": self.unresolved,
        }


def _parse_requirements(path: Path, base: Path, seen: set[Path]) -> DependencyScan:
    scan = DependencyScan(source="requirements.txt")
    resolved = path.resolve()
    if resolved in seen:
        return scan
    seen.add(resolved)
    for raw in read_text(path).splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ", "-r=", "--requirement=")):
            target = line.split("=", 1)[1] if "=" in line.split(" ", 1)[0] else line.split(" ", 1)[1]
            included = (path.parent / target.strip()).resolve()
            try:
                included.relative_to(base.resolve())
            except ValueError:
                continue
            if included.is_file():
                nested = _parse_requirements(included, base, seen)
                scan.resolved.extend(nested.resolved)
                scan.unresolved.extend(nested.unresolved)
            continue
        if line.startswith("-"):
            continue
        pinned = REQUIREMENT_PIN_RE.match(line)
        if pinned:
            scan.resolved.append(
                {"name": normalise_package_name(pinned.group(1)), "version": pinned.group(2)}
            )
            continue
        named = REQUIREMENT_NAME_RE.match(line)
        if named:
            scan.unresolved.append(
                {
                    "name": normalise_package_name(named.group(1)),
                    "specifier": line[named.end():].strip(),
                }
            )
    return scan


def _parse_uv_lock(path: Path) -> DependencyScan:
    """Read ``[[package]]`` name/version pairs out of a uv lockfile.

    ``tomllib`` is stdlib from 3.11 and both plugin repos pin Python 3.12, but
    the toolkit is also run locally, so fall back to a line reader.
    """
    scan = DependencyScan(source="uv.lock")
    text = read_text(path)
    if not text:
        return scan
    try:
        import tomllib

        data = tomllib.loads(text)
    except Exception:
        data = None
    if isinstance(data, dict):
        for package in data.get("package", []) or []:
            name = package.get("name")
            version = package.get("version")
            if name and version:
                scan.resolved.append(
                    {"name": normalise_package_name(str(name)), "version": str(version)}
                )
        return scan

    name = None
    in_package = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            in_package = True
            name = None
            continue
        if stripped.startswith("["):
            in_package = stripped == "[[package]]"
            name = None
            continue
        if not in_package:
            continue
        name_match = UV_LOCK_NAME_RE.match(line)
        if name_match:
            name = name_match.group(1)
            continue
        version_match = UV_LOCK_VERSION_RE.match(line)
        if version_match and name:
            scan.resolved.append(
                {"name": normalise_package_name(name), "version": version_match.group(1)}
            )
            name = None
    return scan


def _parse_pyproject(path: Path) -> DependencyScan:
    scan = DependencyScan(source="pyproject.toml")
    try:
        import tomllib

        data = tomllib.loads(read_text(path))
    except Exception:
        return scan
    requirements: list[str] = []
    project = data.get("project") or {}
    requirements.extend(project.get("dependencies") or [])
    for extra in (project.get("optional-dependencies") or {}).values():
        requirements.extend(extra or [])
    for requirement in requirements:
        pinned = REQUIREMENT_PIN_RE.match(str(requirement))
        if pinned:
            scan.resolved.append(
                {"name": normalise_package_name(pinned.group(1)), "version": pinned.group(2)}
            )
            continue
        named = REQUIREMENT_NAME_RE.match(str(requirement))
        if named:
            scan.unresolved.append(
                {
                    "name": normalise_package_name(named.group(1)),
                    "specifier": str(requirement)[named.end():].strip(),
                }
            )
    return scan


def collect_dependencies(directory: Path) -> DependencyScan:
    """Resolve the dependency set from whichever manifest the plugin ships.

    Preference order is by how exact the input is. ``uv.lock`` is a fully
    resolved transitive closure; ``requirements.txt`` is usually pinned but may
    carry range constraints; ``pyproject.toml`` is mostly ranges.
    """
    lock = directory / "uv.lock"
    if lock.is_file():
        scan = _parse_uv_lock(lock)
        if scan.resolved:
            return _dedupe_dependencies(scan)

    requirements = directory / "requirements.txt"
    if requirements.is_file():
        scan = _parse_requirements(requirements, directory, set())
        if scan.resolved or scan.unresolved:
            return _dedupe_dependencies(scan)

    pyproject = directory / "pyproject.toml"
    if pyproject.is_file():
        return _dedupe_dependencies(_parse_pyproject(pyproject))

    return DependencyScan()


def _dedupe_dependencies(scan: DependencyScan) -> DependencyScan:
    seen_resolved = set()
    resolved = []
    for item in scan.resolved:
        key = (item["name"], item["version"])
        if key not in seen_resolved:
            seen_resolved.add(key)
            resolved.append(item)
    seen_unresolved = set()
    unresolved = []
    for item in scan.unresolved:
        if item["name"] in seen_resolved or item["name"] in seen_unresolved:
            continue
        seen_unresolved.add(item["name"])
        unresolved.append(item)
    scan.resolved = sorted(resolved, key=lambda item: (item["name"], item["version"]))
    scan.unresolved = sorted(unresolved, key=lambda item: item["name"])
    return scan
