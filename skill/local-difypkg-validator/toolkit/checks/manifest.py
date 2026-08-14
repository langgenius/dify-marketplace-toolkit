"""Manifest fields a Marketplace reviewer would otherwise have to eyeball.

Values are read through ``yq`` rather than a YAML parser so that the check sees
exactly the document the plugin runtime sees, including anchors and merge keys.
A missing ``yq`` or an unparseable manifest surfaces as a single error instead of
a traceback, because the reviewer's next action is the same either way.

``author`` may not contain ``dify`` or ``langgenius``: those namespaces imply
first-party authorship. ``privacy`` accepts a URL or an in-package file, and the
in-package case is followed: a file that exists but still carries the template
placeholder is worse than no file at all, since it looks answered. The keyword
sweep over that file is deliberately a warning -- a policy can be honest and
still avoid every word on the list.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from toolkit.findings import Findings
from toolkit.checks.source_hosts import SOURCE_REPOSITORY_URL_RE, unsupported_repo_error

REQUIRED_FIELDS = {
    "author": ".author",
    "name": ".name",
    "version": ".version",
    "type": ".type",
    "icon": ".icon",
    "plugins": ".plugins",
    "privacy": ".privacy",
    "repo": ".repo",
    "contact": ".contact",
    "label.en_US": ".label.en_US",
    "description.en_US": ".description.en_US",
    "meta.version": ".meta.version",
    "meta.arch": ".meta.arch",
    "meta.runner.language": ".meta.runner.language",
    "meta.runner.version": ".meta.runner.version",
    "meta.runner.entrypoint": ".meta.runner.entrypoint",
}

RECOMMENDED_FIELDS = {
    "meta.minimum_dify_version": ".meta.minimum_dify_version",
}

PRIVACY_TEMPLATE_MARKERS = (
    "please fill in the privacy policy",
)

PRIVACY_DISCLOSURE_KEYWORDS = (
    "collect",
    "collection",
    "personal data",
    "user data",
    "data collected",
    "store",
    "storage",
    "retain",
    "retention",
    "persist",
    "log",
    "logging",
    "third party",
    "third-party",
    "share",
    "send",
    "transmit",
    "external service",
    "no user data collected",
    "does not collect",
    "do not collect",
    "not collect any user data",
)

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def yq_value(manifest_path: Path, expression: str) -> str:
    try:
        result = subprocess.run(
            ["yq", "-r", f"{expression} // \"\"", str(manifest_path)],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as err:
        raise RuntimeError("yq command not found") from err
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"failed to read {expression}")
    return result.stdout.strip()


def is_http_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://")


def has_url_scheme(value: str) -> bool:
    return re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", value) is not None


def normalize_local_reference(value: str) -> str:
    if value.startswith("./"):
        return value[2:]
    return value


def is_inside_directory(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


def validate_privacy_policy_file(path: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        content = path.read_text(encoding="utf-8", errors="ignore")

    normalized = content.lower()
    if not normalized.strip():
        errors.append(f"privacy policy file is empty: {path.name}")
        return errors, warnings

    if any(marker in normalized for marker in PRIVACY_TEMPLATE_MARKERS):
        errors.append(f"privacy policy file still contains template placeholder text: {path.name}")
        return errors, warnings

    if not any(keyword in normalized for keyword in PRIVACY_DISCLOSURE_KEYWORDS):
        warnings.append(
            "privacy policy may be missing data collection, storage, logging, third-party sharing, "
            "or no-user-data-collected disclosure"
        )

    return errors, warnings


def validate_manifest(directory: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    manifest_path = directory / "manifest.yaml"

    if not manifest_path.is_file():
        return ["missing required file: manifest.yaml"], warnings

    values: dict[str, str] = {}
    for field_name, expression in REQUIRED_FIELDS.items():
        value = yq_value(manifest_path, expression)
        values[field_name] = value
        if not value:
            errors.append(f"missing required field: {field_name}")

    for field_name, expression in RECOMMENDED_FIELDS.items():
        if not yq_value(manifest_path, expression):
            warnings.append(f"missing recommended field: {field_name}")

    author = values.get("author", "")
    if "langgenius" in author:
        errors.append("author must not contain 'langgenius'")
    if "dify" in author:
        errors.append("author must not contain 'dify'")

    if values.get("type") and values["type"] != "plugin":
        errors.append("type must be 'plugin'")

    repo = values.get("repo", "")
    if repo and not SOURCE_REPOSITORY_URL_RE.search(repo):
        errors.append(unsupported_repo_error(repo))

    contact = values.get("contact", "")
    if contact and not EMAIL_RE.match(contact):
        errors.append("contact must be a valid email address")

    privacy_md_path = directory / "PRIVACY.md"
    if not privacy_md_path.is_file():
        errors.append("missing required file: PRIVACY.md")

    privacy = values.get("privacy", "")
    if privacy:
        if is_http_url(privacy):
            pass
        elif has_url_scheme(privacy):
            errors.append("privacy URL must start with http:// or https://")
        else:
            privacy_reference = Path(normalize_local_reference(privacy))
            privacy_path = directory / privacy_reference
            if privacy_reference.is_absolute() or not is_inside_directory(privacy_path, directory):
                errors.append(f"privacy must reference a file inside the package: {privacy}")
            elif not privacy_path.is_file():
                errors.append(f"privacy references missing file: {privacy}")
            else:
                privacy_errors, privacy_warnings = validate_privacy_policy_file(privacy_path)
                errors.extend(privacy_errors)
                warnings.extend(privacy_warnings)

    return errors, warnings


def scan(args) -> Findings:
    try:
        errors, warnings = validate_manifest(args.directory)
    except RuntimeError as err:
        errors = [f"failed to parse manifest.yaml: {err}"]
        warnings = []
    return Findings(errors=errors, warnings=warnings)
