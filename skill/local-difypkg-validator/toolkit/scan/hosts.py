"""Outbound hostnames a plugin may contact, and the manifest's declaration.

Extraction is *literal only*. A hostname assembled at runtime -- an f-string, an
SDK client, a value from configuration -- cannot be read out of source, so it is
counted rather than guessed; see ``runtime_constructed`` on
:class:`AccessDomainScan`. Reporting that number is what keeps the "Access
Domain" list honest about its own blind spot.

Most of this module is subtraction. A raw URL regex over a plugin returns source
hosting, documentation links, schema namespaces and scraped address tables --
none of which the plugin dials. Each exclusion below removes one of those.
"""

from __future__ import annotations

import ast
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

from toolkit.walk import iter_source_files, read_text, relative_path

# A single source file that mentions more than this many distinct hosts is a
# data payload (a scraped URL table, a fixture), not an access declaration.
MAX_HOSTS_PER_FILE = 20

# Backstop for the whole package.
MAX_HOSTS_PER_PACKAGE = 200

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
