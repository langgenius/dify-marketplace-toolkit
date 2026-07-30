import argparse
import re
import sys
import zipfile
from pathlib import Path


HEADING_RE = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)
CHECKBOX_RE = re.compile(r"^[ \t]*-[ \t]*\[(?P<checked>[ xX])\][ \t]*(?P<label>.+?)[ \t]*$", re.MULTILINE)
VERSION_RE = re.compile(r"^\s*version\s*:\s*[\"']?([^\"'\n#]+)", re.MULTILINE)
VERSION_TOKEN_RE = re.compile(r"(\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?)")


def normalize_heading(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


def sections(pr_body: str) -> dict[str, str]:
    matches = list(HEADING_RE.finditer(pr_body))
    result: dict[str, str] = {}
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(pr_body)
        result[normalize_heading(match.group(1))] = pr_body[start:end]
    return result


def is_version_update(pr_body: str) -> bool:
    section = sections(pr_body).get("submission type", "")
    for match in CHECKBOX_RE.finditer(section):
        if match.group("label").strip().lower() == "version update":
            return match.group("checked").lower() == "x"
    return False


def manifest_version(directory: Path) -> str | None:
    manifest_path = directory / "manifest.yaml"
    if not manifest_path.is_file():
        return None
    return version_from_text(manifest_path.read_text(encoding="utf-8", errors="ignore"))


def version_from_text(text: str) -> str | None:
    match = VERSION_RE.search(text)
    if not match:
        return None
    return match.group(1).strip()


def version_from_package(path: Path) -> str | None:
    try:
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if name.endswith("manifest.yaml"):
                    return version_from_text(archive.read(name).decode("utf-8", errors="ignore"))
    except (OSError, zipfile.BadZipFile):
        return None
    return None


def version_from_filename(path: Path) -> str | None:
    match = VERSION_TOKEN_RE.search(path.stem)
    if not match:
        return None
    return match.group(1)


def version_key(version: str) -> tuple:
    main = re.split(r"[-+]", version, maxsplit=1)[0]
    parts: list[int | str] = []
    for part in main.split("."):
        if part.isdigit():
            parts.append(int(part))
        else:
            parts.append(part)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def previous_versions(package_path: Path) -> list[str]:
    package_dir = package_path.parent
    versions: list[str] = []
    submitted_names = {package_path.name, package_path.name.removesuffix(".zip")}

    for candidate in package_dir.glob("*.difypkg"):
        if candidate.name in submitted_names:
            continue
        version = version_from_package(candidate) or version_from_filename(candidate)
        if version:
            versions.append(version)

    return versions


def validate_version_update(directory: Path, package_path: Path, pr_body_path: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    pr_body = pr_body_path.read_text(encoding="utf-8", errors="ignore")
    if not is_version_update(pr_body):
        return errors, warnings

    current_version = manifest_version(directory)
    if not current_version:
        return ["version update check could not read manifest.yaml version"], warnings

    versions = previous_versions(package_path)
    if not versions:
        warnings.append("version update PR has no previous package version in the same directory to compare against")
        return errors, warnings

    latest_previous = max(versions, key=version_key)
    if version_key(current_version) <= version_key(latest_previous):
        errors.append(
            f"version update must increment manifest.yaml version: current {current_version}, "
            f"latest previous {latest_previous}"
        )

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
    parser = argparse.ArgumentParser(description="Check version update PR version increment.")
    parser.add_argument("-d", "--directory", required=True, help="The unpacked plugin package directory")
    parser.add_argument("--package-path", required=True, help="Submitted .difypkg path, or .difypkg.zip after unpack")
    parser.add_argument("--pr-body-file", required=True, help="Path to a file containing the PR body")
    parser.add_argument("--error-file", help="Optional file path for blocking errors")
    parser.add_argument("--warning-file", help="Optional file path for review warnings")
    args = parser.parse_args()

    directory = Path(args.directory)
    package_path = Path(args.package_path)
    pr_body_path = Path(args.pr_body_file)
    if not directory.is_dir():
        print(f"Package directory not found: {directory}")
        sys.exit(1)
    if not package_path.is_file():
        print(f"Package file not found: {package_path}")
        sys.exit(1)
    if not pr_body_path.is_file():
        print(f"PR body file not found: {pr_body_path}")
        sys.exit(1)

    errors, warnings = validate_version_update(directory, package_path, pr_body_path)
    write_report(args.error_file, errors)
    write_report(args.warning_file, warnings)
    print_report("Version update errors:", errors)
    print_report("Version update warnings:", warnings)
    if errors:
        sys.exit(1)
    print("Version update check passed")


if __name__ == "__main__":
    main()
