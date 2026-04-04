"""Hostname false-positive filters for the URL scanner."""

from __future__ import annotations

import re
from typing import NamedTuple

import tldextract

_NON_HOSTNAME_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp",
    ".yml", ".yaml", ".xml", ".json", ".properties", ".toml",
    ".java", ".py", ".js", ".ts", ".kt", ".scala", ".go", ".rb",
    ".md", ".adoc", ".txt", ".html", ".css", ".sh", ".bat",
    ".jar", ".war", ".ear", ".zip", ".tar", ".gz",
    ".pem", ".jks", ".crt", ".key",
}

_MAVEN_PROPERTY_SUFFIXES = re.compile(
    r"(?:\.version|\.groupId|\.artifactId|\.scope|\.type|\.classifier"
    r"|\.packaging|\.phase)\b"
)

_MARKUP_ANCHOR = re.compile(
    r"(?:\[\[|\<\<|id\s*=\s*['\"]|href\s*=\s*['\"]#)"
)

_INTERNAL_TLDS = {"internal", "local", "corp", "lan", "intranet", "home", "localdomain"}
_ANCHOR_LOOKBEHIND = 30

_ARTIFACT_KEYWORDS = frozenset({
    "test", "plugin", "starter", "autoconfigure", "connector", "adapter",
    "helper", "util", "utils", "commons", "core", "api", "impl", "mock", "stub",
})


class HostnameMatch(NamedTuple):
    text: str
    line: str
    start: int
    end: int
    allowlist: list[str]


def _matches_allowlist(text: str, allowlist: list[str]) -> bool:
    lower = text.lower()
    for entry in allowlist:
        if entry.startswith("^") or entry.endswith("$"):
            if re.search(entry, lower):
                return True
        elif entry in lower:
            return True
    return False


def _looks_like_file_reference(text: str) -> bool:
    lower = text.lower()
    return any(lower.endswith(ext) for ext in _NON_HOSTNAME_EXTENSIONS)


def _looks_like_maven_property(text: str, line: str, match_end: int) -> bool:
    if _MAVEN_PROPERTY_SUFFIXES.search(text):
        return True
    return bool(_MAVEN_PROPERTY_SUFFIXES.match(line[match_end:]))


def _inside_markup_anchor(line: str, match_start: int) -> bool:
    prefix = line[:match_start]
    return bool(_MARKUP_ANCHOR.search(prefix[-_ANCHOR_LOOKBEHIND:] if len(prefix) > _ANCHOR_LOOKBEHIND else prefix))


def _is_artifact_domain(domain: str, suffix: str) -> bool:
    if suffix in _INTERNAL_TLDS or not suffix:
        return False
    return domain in _ARTIFACT_KEYWORDS or any(
        domain.endswith(f"-{k}") or domain.startswith(f"{k}-") for k in _ARTIFACT_KEYWORDS
    )


def _looks_like_artifact_name(text: str) -> bool:
    if "." not in text:
        return False
    extracted = tldextract.extract(text)
    domain = extracted.domain.lower() if extracted.domain else ""
    suffix = extracted.suffix.lower() if extracted.suffix else ""
    return _is_artifact_domain(domain, suffix)


def is_false_positive_hostname(match: HostnameMatch) -> bool:
    """Return True if the matched hostname is almost certainly a false positive."""
    return (
        _matches_allowlist(match.text, match.allowlist)
        or _looks_like_file_reference(match.text)
        or _looks_like_maven_property(match.text, match.line, match.end)
        or _inside_markup_anchor(match.line, match.start)
        or _looks_like_artifact_name(match.text)
    )
