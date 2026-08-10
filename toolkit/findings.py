"""The one value every check returns.

Before this existed each check returned a bare ``(errors, warnings)`` tuple and
each of the fourteen CLI scripts re-implemented the same forty lines to print
it, write it to two files and pick an exit code. The tuple was already the
contract; it just had no name, so nothing could be attached to it.

Naming it buys two things the tuple could not: a single place to add
``to_json`` -- which every check gains at once rather than fourteen times --
and a single definition of what "passed" means.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Findings:
    """Blocking errors and review warnings from one check.

    ``errors`` are objective failures that must be fixed before a plugin can be
    published. ``warnings`` need a human to look; a check that cannot decide on
    its own belongs here rather than raising the stakes on a guess.
    """

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Whether the check found nothing blocking. Warnings do not count."""
        return not self.errors

    def extend(self, other: "Findings") -> "Findings":
        """Fold another result in. Returns self so calls can be chained."""
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        return self

    def to_json(self) -> dict:
        return {
            "status": "ok" if self.ok else "failed",
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


def from_pair(errors: list[str], warnings: list[str]) -> Findings:
    """Adapter for scan functions that still hand back the old tuple."""
    return Findings(errors=list(errors), warnings=list(warnings))
