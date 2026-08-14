"""Hosts accepted as plugin source repositories.

This list is the admission policy for where a Marketplace plugin's source may
live, shared by the manifest check (``repo`` field) and the README check
(``Source:`` link). It is data, not code: admitting a vendor's self-hosted
forge is a one-line reviewed PR here, auditable in git history, instead of a
patch to two regexes.

Hosts are matched exactly (plus an optional ``www.`` prefix). A private
instance is unverifiable from CI either way -- the point of the list is that a
maintainer explicitly admitted the host, not that the URL was fetched.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

ALLOWED_SOURCE_HOSTS = (
    # public forges
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "gitee.com",
    "codeberg.org",
    "git.sr.ht",
    # vendor self-hosted instances, admitted individually
    "gitlab.anchnet.com",  # anspire plugins (langgenius/dify-plugins#2887)
)

_HOST_ALTERNATION = "|".join(re.escape(host) for host in ALLOWED_SOURCE_HOSTS)

# Whole-value form for manifest fields: the field must be nothing but the URL.
SOURCE_REPOSITORY_URL_RE = re.compile(
    rf"^https?://(?:www\.)?(?:{_HOST_ALTERNATION})/[^\s)>\"]+$",
    re.IGNORECASE,
)

# Prose form for READMEs: the URL appears somewhere in the document.
SOURCE_REPOSITORY_LINK_RE = re.compile(
    rf"https?://(?:www\.)?(?:{_HOST_ALTERNATION})/[^\s)>\"]+",
    re.IGNORECASE,
)

ADDITION_HINT = (
    "to request a new host, open a PR against "
    "langgenius/dify-marketplace-toolkit adding it to toolkit/checks/source_hosts.py"
)


def allowed_hosts_display() -> str:
    return ", ".join(ALLOWED_SOURCE_HOSTS)


def url_host(value: str) -> str:
    """Best-effort hostname for error messages; falls back to the raw value."""
    try:
        return urlsplit(value).hostname or value
    except ValueError:
        return value


def unsupported_repo_error(repo: str) -> str:
    return (
        f"repo host `{url_host(repo)}` is not an allowed source repository host "
        f"(allowed: {allowed_hosts_display()}); {ADDITION_HINT}"
    )
