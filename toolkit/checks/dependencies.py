"""Dependency policy for what a plugin is allowed to install at runtime.

The hard rules are about *reproducibility and provenance*: a ``git+`` or direct
URL requirement points at content that can change under the pinned reference, so
the artifact a reviewer approved is not the artifact a user installs. Those
block. Editable installs and local paths are only warnings -- monorepo layouts
use them legitimately, and a human can tell the two cases apart.

Version constraints are graded rather than binary: no constraint at all blocks,
because the next release of any transitive dependency becomes an unreviewed
change; a lower bound alone only warns, since that is the common and mostly
defensible style. ``dify-plugin`` is special-cased to a floor of 0.9.0, below
which the SDK lacks capabilities the platform now assumes.

``LARGE_DEPENDENCIES`` is a judgement list, not a security list: those packages
are hundreds of megabytes and dominate install time, so they get a human's
attention rather than an automatic verdict.

Both requirements files and ``pyproject.toml`` are read, including Poetry's
table forms, because a plugin declaring dependencies in either place installs
them just the same. ``-r`` includes are followed with a ``seen`` set, so a cycle
terminates instead of recursing forever, and includes escaping the package are
reported rather than read.
"""

from __future__ import annotations

import re
from pathlib import Path

from toolkit.findings import Findings

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - GitHub runners should use Python 3.11+.
    tomllib = None


VERSION_OPERATOR_RE = re.compile(r"(===|==|~=|!=|<=|>=|<|>|\^)")
DIRECT_URL_RE = re.compile(r"(^|\s@)\s*(?:https?|ftp|file)://", re.IGNORECASE)
GIT_INSTALL_RE = re.compile(r"git\+", re.IGNORECASE)
LOCAL_PATH_RE = re.compile(r"(^|\s@)\s*(?:\./|\.\./|/)")
ONLY_LOWER_BOUND_RE = re.compile(r"^([^<>=!~]+)?(>=|>)\s*[^,]+$", re.IGNORECASE)
PACKAGE_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)")
MIN_DIFY_PLUGIN_VERSION = (0, 9, 0)

LARGE_DEPENDENCIES = {
    "chromadb",
    "faiss-cpu",
    "faiss-gpu",
    "jax",
    "llama-cpp-python",
    "opencv-contrib-python",
    "opencv-python",
    "opencv-python-headless",
    "paddlepaddle",
    "playwright",
    "pyppeteer",
    "selenium",
    "spacy",
    "tensorflow",
    "tensorflow-cpu",
    "torch",
    "torchaudio",
    "torchvision",
    "transformers",
}

IGNORED_REQUIREMENT_PREFIXES = (
    "-c ",
    "--constraint ",
    "--extra-index-url ",
    "--find-links ",
    "--index-url ",
    "--no-binary ",
    "--only-binary ",
    "--trusted-host ",
    "--use-pep517",
    "--use-feature ",
)


def relative_path(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def strip_inline_comment(line: str) -> str:
    if " #" not in line:
        return line.strip()
    return line.split(" #", 1)[0].strip()


def package_name(requirement: str) -> str:
    if " @ " in requirement:
        requirement = requirement.split(" @ ", 1)[0]
    match = PACKAGE_NAME_RE.match(requirement)
    if not match:
        return ""
    return match.group(1).lower().replace("_", "-")


def version_tuple(value: str) -> tuple[int, ...]:
    parts = []
    for part in re.split(r"[.+-]", value):
        if not part.isdigit():
            break
        parts.append(int(part))
    return tuple(parts)


def dify_plugin_lower_bound(requirement: str) -> str | None:
    match = re.search(r"(?:>=|==)\s*([0-9][0-9A-Za-z.+-]*)", requirement)
    if not match:
        return None
    return match.group(1)


def is_requirement_option(requirement: str) -> bool:
    return requirement.startswith(IGNORED_REQUIREMENT_PREFIXES)


def is_include(requirement: str) -> bool:
    return requirement.startswith("-r ") or requirement.startswith("--requirement ")


def include_target(requirement: str) -> str:
    if requirement.startswith("-r "):
        return requirement[3:].strip()
    return requirement[len("--requirement ") :].strip()


def validate_requirement(requirement: str, source: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    if GIT_INSTALL_RE.search(requirement):
        errors.append(f"{source}: git-based install is not allowed: {requirement}")
        return errors, warnings

    if DIRECT_URL_RE.search(requirement):
        errors.append(f"{source}: direct URL install is not allowed: {requirement}")
        return errors, warnings

    if requirement.startswith("-e ") or requirement.startswith("--editable "):
        warnings.append(f"{source}: editable install requires reviewer approval: {requirement}")
        return errors, warnings

    if LOCAL_PATH_RE.search(requirement):
        warnings.append(f"{source}: local path dependency requires reviewer approval: {requirement}")
        return errors, warnings

    if is_requirement_option(requirement) or is_include(requirement):
        return errors, warnings

    name = package_name(requirement)
    if name in LARGE_DEPENDENCIES:
        warnings.append(f"{source}: large runtime dependency requires reviewer approval: {name}")

    if name == "dify-plugin":
        lower_bound = dify_plugin_lower_bound(requirement)
        if lower_bound is None or version_tuple(lower_bound) < MIN_DIFY_PLUGIN_VERSION:
            errors.append(f"{source}: dify_plugin dependency must be >= 0.9.0: {requirement}")
            return errors, warnings

    if not VERSION_OPERATOR_RE.search(requirement):
        errors.append(f"{source}: dependency has no version constraint: {requirement}")
    elif ONLY_LOWER_BOUND_RE.match(requirement):
        warnings.append(f"{source}: dependency has only a lower-bound version constraint: {requirement}")

    return errors, warnings


def read_requirements(path: Path, base: Path, seen: set[Path]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    resolved = path.resolve()
    if resolved in seen:
        return errors, warnings
    seen.add(resolved)

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    for line_number, raw_line in enumerate(lines, start=1):
        requirement = strip_inline_comment(raw_line)
        if not requirement or requirement.startswith("#"):
            continue
        source = f"{relative_path(path, base)}:{line_number}"

        if is_include(requirement):
            target = include_target(requirement)
            included_path = (path.parent / target).resolve()
            try:
                included_path.relative_to(base.resolve())
            except ValueError:
                warnings.append(f"{source}: referenced requirements file is outside the package: {target}")
                continue
            if not included_path.is_file():
                warnings.append(f"{source}: referenced requirements file is missing: {target}")
                continue
            included_errors, included_warnings = read_requirements(included_path, base, seen)
            errors.extend(included_errors)
            warnings.extend(included_warnings)
            continue

        requirement_errors, requirement_warnings = validate_requirement(requirement, source)
        errors.extend(requirement_errors)
        warnings.extend(requirement_warnings)

    return errors, warnings


def pyproject_dependencies(data: dict) -> list[tuple[str, str]]:
    dependencies: list[tuple[str, str]] = []

    project = data.get("project")
    if isinstance(project, dict):
        for dependency in project.get("dependencies", []) or []:
            if isinstance(dependency, str):
                dependencies.append(("project.dependencies", dependency))

        optional_dependencies = project.get("optional-dependencies")
        if isinstance(optional_dependencies, dict):
            for group, group_dependencies in optional_dependencies.items():
                for dependency in group_dependencies or []:
                    if isinstance(dependency, str):
                        dependencies.append((f"project.optional-dependencies.{group}", dependency))

    dependency_groups = data.get("dependency-groups")
    if isinstance(dependency_groups, dict):
        for group, group_dependencies in dependency_groups.items():
            for dependency in group_dependencies or []:
                if isinstance(dependency, str):
                    dependencies.append((f"dependency-groups.{group}", dependency))

    poetry = data.get("tool", {}).get("poetry") if isinstance(data.get("tool"), dict) else None
    if isinstance(poetry, dict):
        for section_name in ("dependencies", "group"):
            section = poetry.get(section_name)
            if not isinstance(section, dict):
                continue
            if section_name == "dependencies":
                for name, value in section.items():
                    if name.lower() == "python":
                        continue
                    dependencies.append((f"tool.poetry.dependencies.{name}", poetry_dependency(name, value)))
            else:
                for group_name, group_data in section.items():
                    group_dependencies = group_data.get("dependencies") if isinstance(group_data, dict) else None
                    if not isinstance(group_dependencies, dict):
                        continue
                    for name, value in group_dependencies.items():
                        dependencies.append(
                            (f"tool.poetry.group.{group_name}.dependencies.{name}", poetry_dependency(name, value))
                        )

        dev_dependencies = poetry.get("dev-dependencies")
        if isinstance(dev_dependencies, dict):
            for name, value in dev_dependencies.items():
                dependencies.append((f"tool.poetry.dev-dependencies.{name}", poetry_dependency(name, value)))

    return dependencies


def poetry_dependency(name: str, value: object) -> str:
    if isinstance(value, str):
        return f"{name}{value if value.startswith(('=', '<', '>', '~', '!')) else ' ' + value}"
    if isinstance(value, dict):
        if "git" in value:
            ref = value.get("rev") or value.get("tag") or value.get("branch") or ""
            return f"{name} @ git+{value['git']}{('@' + ref) if ref else ''}"
        if "url" in value:
            return f"{name} @ {value['url']}"
        if "path" in value:
            return f"{name} @ {value['path']}"
        version = value.get("version", "")
        return f"{name}{version if isinstance(version, str) else ''}"
    return name


def read_pyproject(path: Path, base: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    if tomllib is None:
        return errors, [f"{relative_path(path, base)}: cannot parse pyproject.toml without Python tomllib"]

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except tomllib.TOMLDecodeError as err:
        return [f"{relative_path(path, base)}: failed to parse pyproject.toml: {err}"], warnings

    for source, dependency in pyproject_dependencies(data):
        dependency_errors, dependency_warnings = validate_requirement(
            dependency,
            f"{relative_path(path, base)}:{source}",
        )
        errors.extend(dependency_errors)
        warnings.extend(dependency_warnings)

    return errors, warnings


def validate_dependencies(directory: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    requirements_path = directory / "requirements.txt"
    if requirements_path.is_file():
        requirement_errors, requirement_warnings = read_requirements(requirements_path, directory, set())
        errors.extend(requirement_errors)
        warnings.extend(requirement_warnings)

    pyproject_path = directory / "pyproject.toml"
    if pyproject_path.is_file():
        pyproject_errors, pyproject_warnings = read_pyproject(pyproject_path, directory)
        errors.extend(pyproject_errors)
        warnings.extend(pyproject_warnings)

    return errors, warnings


def scan(args) -> Findings:
    errors, warnings = validate_dependencies(args.directory)
    return Findings(errors=errors, warnings=warnings)
