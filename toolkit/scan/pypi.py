"""Resolve range constraints to the version an install would pick today.

A range like ``urllib3>=1.26`` cannot be looked up in a vulnerability database
as-is, but leaving every range in ``unresolved`` marks 87 of 87 measured
community plugins as unscannable. This module asks the PyPI JSON API which
published versions exist and picks the **latest final release that satisfies
the constraint** — the version a fresh ``pip install`` would choose at scan
time. The result carries ``basis="range_inferred"`` plus the original
``specifier`` so the Marketplace can tell an inferred version from a locked
one, and ``unresolved`` narrows to "we could not determine a version at all":
the specifier does not parse, the index was unreachable, or no final release
satisfies it.

Stdlib only, like the rest of the toolkit. The specifier grammar is the PEP
440 subset the plugin corpus actually uses: comma-separated ``>=``, ``>``,
``<=``, ``<``, ``==``, ``!=``, ``~=`` clauses plus the ``==X.*`` / ``!=X.*``
wildcards, compared on numeric release tuples. Anything richer — URL
references, environment markers, epochs, pre-release clauses — stays
unresolved rather than being guessed at.
"""

from __future__ import annotations

import json
import re
import urllib.request

PYPI_API = "https://pypi.org/pypi"
DEFAULT_TIMEOUT = 10

# A final release: numeric dot-separated segments only. Anything carrying a
# pre-release, dev, post or local marker (3.0.0a1, 2.0.dev1, 1.0.post2,
# 1.0+local) fails this and is never inferred.
_FINAL_VERSION_RE = re.compile(r"^\d+(\.\d+)*$")
_WILDCARD_RE = re.compile(r"^(==|!=)\s*(\d+(?:\.\d+)*)\.\*$")
_CLAUSE_RE = re.compile(r"^(>=|<=|==|!=|~=|>|<)\s*(\d+(?:\.\d+)*)$")
_EXTRAS_RE = re.compile(r"^\[[^\]]*\]")


def _release_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _padded(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)), right + (0,) * (width - len(right))


def parse_specifier(text: str) -> list[tuple[str, tuple[int, ...]]] | None:
    """Parse a specifier into ``(operator, release_tuple)`` clauses.

    Returns ``None`` when the text is outside the supported subset — the
    caller must keep the dependency unresolved rather than mis-read the
    constraint. An empty specifier is valid and means "any version".
    Wildcard clauses come back with ``==*`` / ``!=*`` operators so matching
    can treat the tuple as a prefix instead of a point.
    """
    stripped = _EXTRAS_RE.sub("", text.strip()).strip()
    if not stripped:
        return []
    # Environment markers and URL references pick a version by rules this
    # subset does not implement.
    if ";" in stripped or "@" in stripped:
        return None
    clauses: list[tuple[str, tuple[int, ...]]] = []
    for part in stripped.split(","):
        part = part.strip().strip("()").strip()
        if not part:
            return None
        wildcard = _WILDCARD_RE.match(part)
        if wildcard:
            clauses.append((wildcard.group(1) + "*", _release_tuple(wildcard.group(2))))
            continue
        clause = _CLAUSE_RE.match(part)
        if clause is None:
            return None
        operator, release = clause.group(1), _release_tuple(clause.group(2))
        if operator == "~=" and len(release) < 2:
            return None
        clauses.append((operator, release))
    return clauses


def _satisfies(version: tuple[int, ...], clauses: list[tuple[str, tuple[int, ...]]]) -> bool:
    for operator, bound in clauses:
        if operator in ("==*", "!=*"):
            padded = version + (0,) * max(0, len(bound) - len(version))
            is_prefix = padded[: len(bound)] == bound
            if is_prefix != (operator == "==*"):
                return False
            continue
        if operator == "~=":
            # ~=X.Y(.Z) is >=X.Y(.Z) plus a prefix match on all but the last
            # released segment.
            left, right = _padded(version, bound)
            if left < right:
                return False
            prefix = bound[:-1]
            padded = version + (0,) * max(0, len(prefix) - len(version))
            if padded[: len(prefix)] != prefix:
                return False
            continue
        left, right = _padded(version, bound)
        if operator == ">=" and not left >= right:
            return False
        if operator == ">" and not left > right:
            return False
        if operator == "<=" and not left <= right:
            return False
        if operator == "<" and not left < right:
            return False
        if operator == "==" and left != right:
            return False
        if operator == "!=" and left == right:
            return False
    return True


def fetch_release_data(name: str, *, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Fetch the PyPI JSON API document for one package."""
    request = urllib.request.Request(
        f"{PYPI_API}/{name}/json",
        headers={"User-Agent": "dify-marketplace-toolkit"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def resolve_ranges(unresolved: list[dict], fetch=None) -> tuple[list[dict], list[dict]]:
    """Infer versions for range-constrained dependencies.

    Takes the ``unresolved`` list (``[{name, specifier}]``) and returns
    ``(resolved, still_unresolved)``. Each inferred entry carries
    ``basis="range_inferred"`` and keeps the original ``specifier``; every
    failure mode — unparsable specifier, index error, no satisfying final
    release — leaves the item in ``still_unresolved`` untouched.

    ``fetch`` takes a package name and returns the parsed PyPI JSON document;
    it is injected so tests never touch the network.
    """
    if fetch is None:
        fetch = fetch_release_data
    resolved: list[dict] = []
    remaining: list[dict] = []
    for item in unresolved:
        name = item.get("name") or ""
        specifier = item.get("specifier") or ""
        clauses = parse_specifier(specifier)
        if not name or clauses is None:
            remaining.append(item)
            continue
        try:
            data = fetch(name)
        except Exception:  # noqa: BLE001 - any index failure means "undetermined"
            remaining.append(item)
            continue
        releases = (data or {}).get("releases") or {}
        best = None
        for version, files in releases.items():
            if not _FINAL_VERSION_RE.match(version):
                continue
            if isinstance(files, list) and not files:
                # A release with no distribution files cannot be installed.
                continue
            release = _release_tuple(version)
            if not _satisfies(release, clauses):
                continue
            if best is None:
                best = (release, version)
            else:
                left, right = _padded(release, best[0])
                if left > right:
                    best = (release, version)
        if best is None:
            remaining.append(item)
            continue
        resolved.append(
            {
                "name": name,
                "version": best[1],
                "basis": "range_inferred",
                "specifier": specifier,
            }
        )
    return resolved, remaining


def make_resolver(*, enabled: bool = True, timeout: int = DEFAULT_TIMEOUT):
    """Build the callable :func:`toolkit.scan.report.build_security_report` expects."""
    if not enabled:
        return None

    def _resolve(unresolved: list[dict]) -> tuple[list[dict], list[dict]]:
        return resolve_ranges(
            unresolved, fetch=lambda name: fetch_release_data(name, timeout=timeout)
        )

    return _resolve
