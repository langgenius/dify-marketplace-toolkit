"""What the local validator runs, in what order, and when it may skip.

This table replaced two hand-maintained lists plus an ``if`` that special-cased
the one check needing a PR body -- and, next to that ``if``, a hand-written
sentence explaining the skip. The two could drift, and the reader had to hold
both in mind to answer "what actually ran".

Order is part of the contract: it is the order of rows in the summary table
that reviewers read. Blocking checks come first so the first failure a reader
meets is one that stops publication.

Category and severity live here as data rather than as directories, because
both change. A check can be promoted from warning to blocking, or reclassified,
without a file move that would break the CLI paths other repositories hardcode.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

BLOCKING = "blocking"
WARNING = "warning"

SCRIPT = "script"
COMPILE = "compile"


@dataclass(frozen=True)
class Context:
    """Everything a check might need beyond the unpacked directory."""

    package_path: Path
    pr_body_file: Path | None = None
    offline: bool = False


@dataclass(frozen=True)
class Check:
    """One row of the local validation run.

    ``name`` is the report-file prefix and the identifier in the summary table.
    ``script`` is resolved under ``validator/``. ``requires`` names a
    :class:`Context` attribute that must be set for the check to run at all;
    when it is missing the check is skipped and ``skip_reason`` is what the
    report says about it, so the explanation cannot drift from the condition.
    """

    name: str
    script: str
    kind: str
    runner: str = SCRIPT
    requires: str | None = None
    skip_reason: str = ""
    extra_args: Callable[[Context], list[str]] | None = field(default=None, compare=False)

    @property
    def blocking(self) -> bool:
        return self.kind == BLOCKING

    def available(self, context: Context) -> bool:
        return self.requires is None or getattr(context, self.requires, None) is not None

    def args(self, context: Context) -> list[str]:
        return self.extra_args(context) if self.extra_args else []


CHECKS: tuple[Check, ...] = (
    Check(
        "package_contents",
        "check-package-contents.py",
        BLOCKING,
        extra_args=lambda ctx: ["--package-file", str(ctx.package_path)],
    ),
    Check("package_secrets", "check-package-secrets.py", BLOCKING),
    Check("package_binaries", "check-package-binaries.py", BLOCKING),
    Check("manifest_metadata", "check-manifest-metadata.py", BLOCKING),
    Check("readme_metadata", "check-readme-metadata.py", BLOCKING),
    Check("package_dependencies", "check-package-dependencies.py", BLOCKING),
    Check("python_compile", "", BLOCKING, runner=COMPILE),
    Check("python_safety", "check-python-safety-warnings.py", WARNING),
    Check("prohibited_financial_activity", "check-prohibited-financial-activity.py", WARNING),
    Check("access_domains", "check-access-domains.py", WARNING),
    Check(
        "dependency_vulnerabilities",
        "check-dependency-vulnerabilities.py",
        WARNING,
        extra_args=lambda ctx: ["--offline"] if ctx.offline else [],
    ),
    Check(
        "sensitive_capabilities",
        "check-sensitive-capabilities.py",
        BLOCKING,
        requires="pr_body_file",
        skip_reason="sensitive capability disclosure blocking check requires --pr-body-file",
        extra_args=lambda ctx: ["--pr-body-file", str(ctx.pr_body_file)],
    ),
)

# Checks that cannot run from a package alone. Stated in the report so a reader
# never mistakes "the local validator passed" for "review will pass".
OUT_OF_SCOPE: tuple[str, ...] = (
    "PR title/body language and template checks require GitHub PR metadata",
    "Marketplace duplicate-version check requires Marketplace/PR workflow context",
    "plugin install and upload-package tests are not run by this local validator",
)
