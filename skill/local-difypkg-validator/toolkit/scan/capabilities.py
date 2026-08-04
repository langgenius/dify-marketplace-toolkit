"""Sensitive-capability signals: what a plugin's code is able to reach for.

Counting, not judging. The disclosure check compares these counts against what
the PR body admits to; the plugin page shows them as categories. Neither is
decided here.

Precision is the whole game. Matching SQL keywords in YAML once inflated the
"SQL or database access" hit rate to 67% against a true 5.4%, because a
parameter of ``type: select`` reads as a SELECT statement. Every rule is
therefore scoped to the file kinds where the signal can be real.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from toolkit.walk import CODE_SUFFIXES, iter_source_files, read_text, relative_path

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
