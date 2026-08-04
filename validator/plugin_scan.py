"""Static scan primitives shared by the validators and the uploader.

Stdlib only. This module is imported by validator CLIs, by
``uploader/upload-package.py`` and by the local orchestrator, all of which run
in CI environments that install nothing beyond ``requests``.

Three products, one walk of the package tree:

* :func:`extract_access_domains` — outbound hostnames a plugin may connect to
  (Marketplace plugin page, "Access Domain" block).
* :func:`collect_dependencies` — the resolved dependency set, ready for a
  vulnerability database lookup.
* :func:`scan_capabilities` — the sensitive-capability signals the plugin
  review flow already relies on.

Extraction is *literal only*. A hostname that is assembled at runtime
(``f"{self.base_url}/v1"``, an SDK client, a value from configuration) cannot
be read out of source, so it is counted instead of guessed — see
``runtime_constructed`` on :class:`AccessDomainScan`.
"""

from __future__ import annotations

import ast
import ipaddress
import json
import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

SCANNER_VERSION = "1.0.0"

# --------------------------------------------------------------------------
# file walk
# --------------------------------------------------------------------------

SCAN_SUFFIXES = {".py", ".yaml", ".yml", ".json", ".toml", ".js", ".ts"}
CODE_SUFFIXES = {".py", ".js", ".ts"}

# Names skipped wherever they appear. Hidden directories are skipped by rule,
# which also covers ``.venv``, ``.venv312``, ``.tox`` and scratch dirs plugins
# occasionally ship.
SKIP_DIR_NAMES = {
    "venv",
    "env",
    "node_modules",
    "vendor",
    "__pycache__",
    "site-packages",
    "dist-packages",
}

# Dependency trees get vendored into packages surprisingly often (a whole
# ``Lib/site-packages`` tree, a ``vendor/*.js`` bundle). Scanning them reports
# the *dependency's* hostnames as the plugin's, which is both wrong and
# unbounded — one package yielded 4657 hosts before this rule existed.
SKIP_PATH_PARTS = {"site-packages", "dist-packages"}

MAX_FILE_BYTES = 1024 * 1024

# A single source file that mentions more than this many distinct hosts is a
# data payload (a scraped URL table, a fixture), not an access declaration.
MAX_HOSTS_PER_FILE = 20

# Backstop for the whole package.
MAX_HOSTS_PER_PACKAGE = 200

DEPENDENCY_FILENAMES = {"requirements.txt", "pyproject.toml", "uv.lock"}


def _skip_dir(name: str) -> bool:
    return name.startswith(".") or name.lower() in SKIP_DIR_NAMES


def iter_source_files(root: Path):
    """Yield scannable source files under ``root``, pruning vendored trees."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
        parts = {p.lower() for p in Path(dirpath).parts}
        if parts & SKIP_PATH_PARTS:
            dirnames[:] = []
            continue
        base = Path(dirpath)
        for filename in filenames:
            if filename.startswith("."):
                continue
            path = base / filename
            if path.suffix.lower() not in SCAN_SUFFIXES:
                continue
            if filename in DEPENDENCY_FILENAMES:
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def relative_path(path: Path, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


def unpack_package(package_path: Path, target_dir: Path) -> None:
    """Extract a ``.difypkg`` (a zip) with zip-slip protection."""
    with zipfile.ZipFile(package_path) as archive:
        for member in archive.infolist():
            member_path = Path(member.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise RuntimeError(f"Unsafe path in package: {member.filename}")
        archive.extractall(target_dir)


# --------------------------------------------------------------------------
# hostname extraction
# --------------------------------------------------------------------------

URL_RE = re.compile(
    r"""(?i)\bhttps?://([^\s/?#"'`<>)\]}\\,;*]+|\*\.[^\s/?#"'`<>)\]}\\,;]+)"""
)

HOST_RE = re.compile(r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")

# Hosts that appear in plugin source but are never contacted by the plugin:
# source hosting, documentation, specification namespaces, package mirrors.
EXCLUDED_HOSTS = {
    # source hosting
    "github.com",
    "www.github.com",
    "gist.github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "gitlab.com",
    "bitbucket.org",
    # specification namespaces (XML/JSON schema URLs are identifiers, not endpoints)
    "www.w3.org",
    "w3.org",
    "json-schema.org",
    "schema.org",
    "spdx.org",
    "opensource.org",
    "www.apache.org",
    "apache.org",
    "www.gnu.org",
    "creativecommons.org",
    "purl.org",
    "xmlns.com",
    "schemas.openxmlformats.org",
    # package mirrors / CDNs
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    # local
    "localhost",
    "host.docker.internal",
    "0.0.0.0",
    "broadcasthost",
    # knowledge bases quoted in comments
    "stackoverflow.com",
    "www.stackoverflow.com",
    "en.wikipedia.org",
    "wikipedia.org",
}

EXCLUDED_HOST_SUFFIXES = (
    ".readthedocs.io",
    ".readthedocs.org",
    ".github.io",
    ".gitlab.io",
)

# RFC 2606 / RFC 6761 reserved names. Everything under them is a placeholder.
RESERVED_HOST_SUFFIXES = (
    ".example.com",
    ".example.org",
    ".example.net",
    ".example",
    ".test",
    ".invalid",
    ".localhost",
    ".local",
)
RESERVED_HOSTS = {"example.com", "example.org", "example.net"}

# Documentation subdomains. A plugin links to its vendor's docs constantly and
# never requests them.
EXCLUDED_HOST_LABELS = {"docs", "doc", "developer", "learn"}

# Free redirection services: the name says nothing about who answers it.
DYNAMIC_DNS_SUFFIXES = (
    ".ngrok.io",
    ".ngrok-free.app",
    ".ngrok.app",
    ".duckdns.org",
    ".no-ip.org",
    ".no-ip.com",
    ".no-ip.biz",
    ".hopto.org",
    ".zapto.org",
    ".ddns.net",
    ".trycloudflare.com",
    ".loca.lt",
    ".serveo.net",
    ".localtunnel.me",
    ".pagekite.me",
    ".dynu.net",
    ".freedns.afraid.org",
)

KIND_DOMAIN = "domain"
KIND_WILDCARD = "wildcard"
KIND_IP_PUBLIC = "ip_public"
KIND_IP_PRIVATE = "ip_private"

# YAML keys whose values are links shown to the human, not addresses the
# plugin dials: "where to get your API key", "read the docs", "our repo".
DOC_KEYS = {
    "url",
    "help",
    "privacy",
    "repo",
    "documentation",
    "doc_url",
    "document_url",
    "docs",
    "icon",
    "website",
    "homepage",
    "source",
}
DOC_ANCESTOR_KEYS = {"help", "oauth_schema"}

LOCALE_KEYS = {
    "en_us", "zh_hans", "zh_hant", "ja_jp", "ko_kr", "pt_br", "fr_fr", "de_de",
    "es_es", "ru_ru", "it_it", "vi_vn", "th_th", "tr_tr", "pl_pl", "uk_ua",
    "id_id", "hi_in", "ar_sa", "ro_ro", "sl_si", "fa_ir", "he_il", "nl_nl",
}

YAML_KEY_RE = re.compile(r"^(\s*)(?:-\s+)?([A-Za-z_$][\w .$-]*)\s*:")

# ``$ref``/``$schema`` values are identifiers for a schema document.
SCHEMA_REF_RE = re.compile(r"""(^|[\s"'{,])\$?(?:ref|schema)\s*[:=]""", re.IGNORECASE)


def normalise_host(raw: str) -> str | None:
    host = raw.strip().strip(".").lower()
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if host.startswith("["):
        return None
    if ":" in host:
        host = host.split(":", 1)[0]
    return host or None


def classify_host(host: str) -> tuple[str, bool]:
    """Return ``(kind, keep)``. ``keep`` is False for junk and loopback."""
    if host.startswith("*."):
        return KIND_WILDCARD, bool(HOST_RE.match(host))
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if address.is_loopback:
            # A loopback address is never reachable from the runtime; showing
            # it would read as "this plugin talks to your machine".
            return KIND_IP_PRIVATE, False
        if address.is_private or address.is_link_local:
            return KIND_IP_PRIVATE, True
        return KIND_IP_PUBLIC, True
    if not HOST_RE.match(host):
        return KIND_DOMAIN, False
    return KIND_DOMAIN, True


def is_excluded_host(host: str) -> bool:
    if host in EXCLUDED_HOSTS or host in RESERVED_HOSTS:
        return True
    if host.endswith(EXCLUDED_HOST_SUFFIXES) or host.endswith(RESERVED_HOST_SUFFIXES):
        return True
    return host.split(".")[0] in EXCLUDED_HOST_LABELS


def is_dynamic_dns(host: str) -> bool:
    return host.endswith(DYNAMIC_DNS_SUFFIXES)


def _hosts_in_text(text: str) -> list[str]:
    out = []
    for match in URL_RE.finditer(text):
        host = normalise_host(match.group(1))
        if host:
            out.append(host)
    return out


def _yaml_hosts(text: str) -> list[tuple[int, str]]:
    """Hosts in a YAML document, skipping documentation-valued keys."""
    stack: list[tuple[int, str]] = []
    found: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        match = YAML_KEY_RE.match(line)
        if match:
            indent = len(match.group(1))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            stack.append((indent, match.group(2)))
        segments = [key.lower() for _, key in stack if key.lower() not in LOCALE_KEYS]
        if segments and (
            segments[-1] in DOC_KEYS or DOC_ANCESTOR_KEYS & set(segments)
        ):
            continue
        if SCHEMA_REF_RE.search(line):
            continue
        for host in _hosts_in_text(line):
            found.append((lineno, host))
    return found


def _plain_hosts(text: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or SCHEMA_REF_RE.search(stripped):
            continue
        for host in _hosts_in_text(line):
            found.append((lineno, host))
    return found


_NET_METHODS = {
    "get", "post", "put", "patch", "delete", "head", "options", "request", "stream",
}


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """Ids of the string constants that are docstrings.

    A URL in a docstring documents an API; it is not a request. Comments never
    reach the AST at all, which is the other half of why this is parsed rather
    than grepped.
    """
    ids = set()
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            continue
        body = getattr(node, "body", None)
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            ids.add(id(body[0].value))
    return ids


def _is_network_call(node: ast.Call) -> bool:
    func = node.func
    name = None
    owner = None
    if isinstance(func, ast.Attribute):
        name = func.attr
        if isinstance(func.value, ast.Name):
            owner = func.value.id
        elif isinstance(func.value, ast.Attribute):
            owner = func.value.attr
    elif isinstance(func, ast.Name):
        name = func.id
    if owner in {"requests", "httpx"} and name in _NET_METHODS:
        return True
    if owner == "request" and name in {"urlopen", "Request"}:
        return True
    if owner == "aiohttp" and name == "ClientSession":
        return True
    return name == "urlopen"


def _python_hosts(text: str) -> tuple[list[tuple[int, str]], int, int]:
    """Return ``(hosts, network_callsites, runtime_constructed)``.

    Parsing rather than line-matching fixes three things at once: a call split
    across lines by a formatter still yields its URL, an inline ``# see
    https://…`` comment no longer counts, and a docstring URL no longer counts.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        # Not importable Python (a template, a py2 file). Fall back to lines so
        # the file is not silently invisible.
        return _plain_hosts(text), 0, 0

    docstrings = _docstring_nodes(tree)

    def literal_hosts(node: ast.AST) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        for sub in ast.walk(node):
            if (
                isinstance(sub, ast.Constant)
                and isinstance(sub.value, str)
                and id(sub) not in docstrings
            ):
                for host in _hosts_in_text(sub.value):
                    out.append((getattr(sub, "lineno", 0), host))
        return out

    hosts = literal_hosts(tree)
    callsites = 0
    runtime_constructed = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_network_call(node):
            continue
        callsites += 1
        arguments = list(node.args) + [kw.value for kw in node.keywords]
        if not any(literal_hosts(argument) for argument in arguments):
            runtime_constructed += 1
    return hosts, callsites, runtime_constructed


@dataclass
class DetectedDomain:
    host: str
    kind: str
    sources: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        return {"host": self.host, "kind": self.kind, "sources": self.sources[:3]}


@dataclass
class AccessDomainScan:
    domains: list[DetectedDomain] = field(default_factory=list)
    network_callsites: int = 0
    runtime_constructed: int = 0
    skipped_data_files: int = 0
    truncated: bool = False

    def hosts(self) -> list[str]:
        return [domain.host for domain in self.domains]

    def to_json(self) -> dict:
        return {
            "detected": [domain.to_json() for domain in self.domains],
            "network_callsites": self.network_callsites,
            "runtime_constructed": self.runtime_constructed,
            "skipped_data_files": self.skipped_data_files,
            "truncated": self.truncated,
        }


def extract_access_domains(directory: Path) -> AccessDomainScan:
    """Extract literal outbound hostnames from an unpacked plugin."""
    scan = AccessDomainScan()
    collected: dict[str, DetectedDomain] = {}

    for path in iter_source_files(directory):
        text = read_text(path)
        if not text:
            continue
        suffix = path.suffix.lower()
        if suffix == ".py":
            hits, callsites, runtime_constructed = _python_hosts(text)
            scan.network_callsites += callsites
            scan.runtime_constructed += runtime_constructed
        elif suffix in {".yaml", ".yml"}:
            hits = _yaml_hosts(text)
        else:
            hits = _plain_hosts(text)

        per_file: dict[str, list[str]] = {}
        for lineno, host in hits:
            kind, keep = classify_host(host)
            if not keep or is_excluded_host(host):
                continue
            evidence = f"{relative_path(path, directory)}:{lineno}"
            per_file.setdefault(host, [])
            if evidence not in per_file[host]:
                per_file[host].append(evidence)

        if len(per_file) > MAX_HOSTS_PER_FILE:
            scan.skipped_data_files += 1
            continue

        for host, evidence in per_file.items():
            entry = collected.get(host)
            if entry is None:
                if len(collected) >= MAX_HOSTS_PER_PACKAGE:
                    scan.truncated = True
                    continue
                entry = DetectedDomain(host=host, kind=classify_host(host)[0])
                collected[host] = entry
            for item in evidence:
                if item not in entry.sources:
                    entry.sources.append(item)

    scan.domains = sorted(collected.values(), key=lambda domain: domain.host)
    return scan


# --------------------------------------------------------------------------
# declared domains (manifest ``network.domains``)
# --------------------------------------------------------------------------

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def normalise_declared_domain(raw: str) -> str | None:
    """Accept what an author is likely to write and reduce it to a hostname."""
    value = str(raw or "").strip().strip("\"'")
    if not value:
        return None
    value = _SCHEME_RE.sub("", value)
    value = value.split("/", 1)[0]
    return normalise_host(value)


def read_declared_domains(directory: Path) -> list[str]:
    """Read the optional top-level ``network.domains`` node from manifest.yaml.

    Parsed with a narrow line reader rather than a YAML library: the toolkit has
    no PyYAML and shells out to ``yq`` elsewhere, and this node is a flat list
    of scalars.
    """
    manifest = directory / "manifest.yaml"
    if not manifest.is_file():
        return []
    domains: list[str] = []
    in_network = False
    in_domains = False
    for line in read_text(manifest).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent == 0:
            in_network = stripped.rstrip().rstrip(":") == "network" and stripped.endswith(":")
            in_domains = False
            continue
        if not in_network:
            continue
        if stripped.startswith("-"):
            if in_domains:
                host = normalise_declared_domain(stripped[1:].split("#", 1)[0])
                if host and host not in domains:
                    domains.append(host)
            continue
        key = stripped.split(":", 1)[0].strip()
        in_domains = key == "domains"
        if in_domains:
            inline = stripped.split(":", 1)[1].strip() if ":" in stripped else ""
            if inline.startswith("[") and inline.endswith("]"):
                for item in inline[1:-1].split(","):
                    host = normalise_declared_domain(item)
                    if host and host not in domains:
                        domains.append(host)
                in_domains = False
    return domains


def matches_declaration(host: str, declared: list[str]) -> bool:
    """Is ``host`` covered by a declared entry? ``*.x.com`` covers ``a.x.com``."""
    for entry in declared:
        if entry == host:
            return True
        if entry.startswith("*."):
            suffix = entry[1:]  # ".x.com"
            if host.endswith(suffix) and host != suffix.lstrip("."):
                return True
            if host == entry[2:]:
                return True
    return False


def undeclared_hosts(detected: list[str], declared: list[str]) -> list[str]:
    return [host for host in detected if not matches_declaration(host, declared)]


# --------------------------------------------------------------------------
# dependencies
# --------------------------------------------------------------------------

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


# --------------------------------------------------------------------------
# sensitive capabilities
# --------------------------------------------------------------------------

# ``suffixes`` restricts a category to the file kinds where it can be real.
# SQL and code execution used to be matched in YAML too, where a parameter of
# ``type: select`` reads as a SELECT statement — that single rule inflated the
# "SQL or database access" hit rate to 67% against a true 5.4%.
CAPABILITY_RULES: dict[str, dict] = {
    "command execution": {
        "suffixes": CODE_SUFFIXES,
        "patterns": (
            r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(",
            r"\bos\.(?:system|popen|spawn[a-z_]*|exec[a-z_]*)\s*\(",
            r"\bpty\.spawn\s*\(",
        ),
    },
    "code execution": {
        "suffixes": CODE_SUFFIXES,
        "patterns": (
            # ``(?<![\w.])`` keeps ``re.compile`` / ``model.eval`` out. Bare
            # ``compile(`` was the single largest source of false positives.
            r"(?<![\w.])eval\s*\(",
            r"(?<![\w.])exec\s*\(",
            r"(?<![\w.])compile\s*\(",
            r"\bimportlib\.import_module\s*\(",
            r"\b__import__\s*\(",
            r"\bpickle\.loads?\s*\(",
            r"\bmarshal\.loads?\s*\(",
        ),
    },
    "SQL or database access": {
        "suffixes": CODE_SUFFIXES,
        "patterns": (
            # Each keyword now needs the clause that makes it a statement.
            r"\bSELECT\b[\s\S]{0,200}?\bFROM\b",
            r"\bINSERT\s+INTO\b",
            r"\bUPDATE\s+[\w.\"`\[\]]+\s+SET\b",
            r"\bDELETE\s+FROM\b",
            r"\bDROP\s+(?:TABLE|DATABASE|INDEX)\b",
            r"\bALTER\s+TABLE\b",
            r"\bCREATE\s+(?:TABLE|DATABASE|INDEX)\b",
            r"\b(?:sqlite3|psycopg|psycopg2|pymysql|mysql\.connector|sqlalchemy)\b",
            r"\.execute(?:many)?\s*\(",
        ),
    },
    "SSH or SFTP": {
        "suffixes": CODE_SUFFIXES,
        "patterns": (
            r"\b(?:paramiko|asyncssh)\b",
            r"\bSSHClient\s*\(",
            r"\bpysftp\b",
        ),
    },
    "filesystem operations": {
        "suffixes": CODE_SUFFIXES,
        "patterns": (
            r"(?<![\w.])open\s*\(",
            r"\bos\.(?:remove|unlink|rename|replace|makedirs|listdir|walk)\s*\(",
            r"\bshutil\.(?:copy|copyfile|copytree|move|rmtree)\s*\(",
            r"\bglob\.glob\s*\(",
        ),
    },
    "arbitrary network requests": {
        "suffixes": CODE_SUFFIXES,
        "patterns": (
            r"\brequests\.(?:get|post|put|patch|delete|head|options|request)\s*\(",
            r"\bhttpx\.(?:get|post|put|patch|delete|head|options|request|stream)\s*\(",
            r"\baiohttp\.ClientSession\s*\(",
            r"\burllib\.request\.(?:urlopen|Request)\s*\(",
            r"\burlopen\s*\(",
        ),
    },
    "browser automation": {
        "suffixes": CODE_SUFFIXES,
        "patterns": (
            r"\b(?:playwright|selenium|pyppeteer|webdriver)\b",
            r"\bbrowser\.new_page\s*\(",
            r"\bpage\.goto\s*\(",
        ),
    },
}

# SQL keywords are written in either case inside query strings; identifier-ish
# patterns are not, and matching them case-insensitively is what turned
# ``requests.delete(url)`` into a database access.
CASE_INSENSITIVE_CATEGORIES = {"SQL or database access"}

COMPILED_CAPABILITY_RULES = {
    category: {
        "suffixes": rule["suffixes"],
        "patterns": tuple(
            re.compile(
                pattern,
                re.IGNORECASE if category in CASE_INSENSITIVE_CATEGORIES else 0,
            )
            for pattern in rule["patterns"]
        ),
    }
    for category, rule in CAPABILITY_RULES.items()
}

# How many example lines to keep per category. Counting continues past it.
MAX_SAMPLES_PER_CATEGORY = 20


@dataclass
class CapabilityCategory:
    name: str
    count: int = 0
    samples: list[str] = field(default_factory=list)


def scan_capabilities(directory: Path) -> list[CapabilityCategory]:
    """Count sensitive-capability signals per category.

    Differences from a naive line scan, each of which changed the numbers:

    * a line is attributed to **every** category it matches, not just the first
      one in dict order — ``requests.delete(url)`` used to be filed under SQL
      and its network signal disappeared;
    * the per-category limit caps *stored samples*, not counting, so a busy
      plugin no longer reports a silently truncated total;
    * categories only run against the file kinds where they can be real.
    """
    counters: dict[str, CapabilityCategory] = {
        category: CapabilityCategory(name=category) for category in COMPILED_CAPABILITY_RULES
    }

    for path in iter_source_files(directory):
        suffix = path.suffix.lower()
        applicable = [
            (category, rule)
            for category, rule in COMPILED_CAPABILITY_RULES.items()
            if suffix in rule["suffixes"]
        ]
        if not applicable:
            continue
        text = read_text(path)
        if not text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for category, rule in applicable:
                if not any(pattern.search(stripped) for pattern in rule["patterns"]):
                    continue
                counter = counters[category]
                counter.count += 1
                if len(counter.samples) < MAX_SAMPLES_PER_CATEGORY:
                    counter.samples.append(
                        f"{relative_path(path, directory)}:{lineno}: {stripped[:180]}"
                    )

    return [counter for counter in counters.values() if counter.count]


# --------------------------------------------------------------------------
# report assembly
# --------------------------------------------------------------------------


def build_security_report(
    directory: Path,
    *,
    scanned_at: str,
    vulnerability_lookup=None,
) -> dict:
    """Produce the ``security_report`` payload for one unpacked plugin.

    ``vulnerability_lookup`` takes the resolved dependency list and returns
    ``(vulnerabilities, status)``. It is injected so the scan works offline and
    so the network half can be tested without one.

    Each section carries its own status. A dependency lookup that could not
    reach the database must not make the domain scan look absent — "we did not
    scan" and "we scanned and found nothing" are different answers, and the
    rating downstream treats them differently.
    """
    report: dict = {
        "schema_version": 1,
        "scanner_version": SCANNER_VERSION,
        "scanned_at": scanned_at,
    }

    try:
        domain_scan = extract_access_domains(directory)
        declared = read_declared_domains(directory)
        detected_hosts = domain_scan.hosts()
        access = domain_scan.to_json()
        access["status"] = "ok"
        access["declared"] = declared
        access["undeclared"] = undeclared_hosts(detected_hosts, declared)
        report["access_domains"] = access
    except Exception as error:  # noqa: BLE001 - a scan crash must not block publishing
        report["access_domains"] = {"status": "failed", "error": str(error)[:200]}

    try:
        dependency_scan = collect_dependencies(directory)
        dependencies = dependency_scan.to_json()
        dependencies["database"] = "osv.dev"
        if not dependency_scan.resolved and not dependency_scan.unresolved:
            dependencies["status"] = "skipped"
            dependencies["vulnerabilities"] = []
        elif vulnerability_lookup is None:
            dependencies["status"] = "skipped"
            dependencies["vulnerabilities"] = []
        else:
            vulnerabilities, status = vulnerability_lookup(dependency_scan.resolved)
            dependencies["status"] = status
            dependencies["vulnerabilities"] = vulnerabilities
        report["dependencies"] = dependencies
    except Exception as error:  # noqa: BLE001
        report["dependencies"] = {"status": "failed", "error": str(error)[:200]}

    try:
        categories = scan_capabilities(directory)
        report["capabilities"] = {
            "status": "ok",
            "categories": [
                {"name": item.name, "count": item.count, "samples": item.samples[:5]}
                for item in categories
            ],
        }
    except Exception as error:  # noqa: BLE001
        report["capabilities"] = {"status": "failed", "error": str(error)[:200]}

    return report


def dumps_report(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, separators=(",", ":"))
