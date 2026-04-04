"""Hostname false-positive filters for the URL scanner."""

from __future__ import annotations

import re

import tldextract

# File extensions that disqualify a match from being a hostname
_NON_HOSTNAME_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp",
    ".yml", ".yaml", ".xml", ".json", ".properties", ".toml",
    ".java", ".py", ".js", ".ts", ".kt", ".scala", ".go", ".rb",
    ".md", ".adoc", ".txt", ".html", ".css", ".sh", ".bat",
    ".jar", ".war", ".ear", ".zip", ".tar", ".gz",
    ".pem", ".jks", ".crt", ".key",
}

# Maven property suffixes: if the match is immediately followed by one of
# these, it's a property name, not a hostname.
_MAVEN_PROPERTY_SUFFIXES = re.compile(
    r"(?:\.version|\.groupId|\.artifactId|\.scope|\.type|\.classifier"
    r"|\.packaging|\.phase)\b"
)

# Markup anchor patterns: [[anchor]], <<ref>>, id="anchor", #anchor in URLs
_MARKUP_ANCHOR = re.compile(
    r"(?:\[\[|\<\<|id\s*=\s*['\"]|href\s*=\s*['\"]#)"
)

# Internal TLD suffixes that strongly indicate a hostname
_INTERNAL_TLDS = {"internal", "local", "corp", "lan", "intranet", "home", "localdomain"}

_ARTIFACT_KEYWORDS = frozenset({
    "test", "plugin", "starter", "autoconfigure", "connector", "adapter",
    "helper", "util", "utils", "commons", "core", "api", "impl", "mock", "stub",
})


def _matches_allowlist(text: str, allowlist: list[str]) -> bool:
    """Exact substring or regex match against the hostname allowlist."""
    lower = text.lower()
    for entry in allowlist:
        if entry.startswith("^") or entry.endswith("$"):
            if re.search(entry, lower):
                return True
        elif entry in lower:
            return True
    return False


def _looks_like_file_reference(text: str) -> bool:
    """The matched text ends with a known file extension, not a hostname."""
    lower = text.lower()
    return any(lower.endswith(ext) for ext in _NON_HOSTNAME_EXTENSIONS)


def _looks_like_maven_property(text: str, line: str, match_end: int) -> bool:
    """The match is a Maven property name (e.g. app-utils.version), not a hostname."""
    if _MAVEN_PROPERTY_SUFFIXES.search(text):
        return True
    remainder = line[match_end:]
    return bool(_MAVEN_PROPERTY_SUFFIXES.match(remainder))


def _inside_markup_anchor(line: str, match_start: int) -> bool:
    """The match is preceded by anchor/link syntax ([[, <<, id=, href=#)."""
    prefix = line[:match_start]
    return bool(_MARKUP_ANCHOR.search(prefix[-30:] if len(prefix) > 30 else prefix))


def _looks_like_artifact_name(text: str) -> bool:
    """A dotted match whose TLD is public and whose domain looks like a library name."""
    if "." not in text:
        return False
    extracted = tldextract.extract(text)
    suffix = extracted.suffix.lower() if extracted.suffix else ""
    domain = extracted.domain.lower() if extracted.domain else ""

    if suffix in _INTERNAL_TLDS:
        return False

    if suffix:
        if domain in _ARTIFACT_KEYWORDS:
            return True
        if any(domain.endswith(f"-{k}") or domain.startswith(f"{k}-")
               for k in _ARTIFACT_KEYWORDS):
            return True

    return False


def is_false_positive_hostname(
    text: str,
    line: str,
    match_start: int,
    match_end: int,
    allowlist: list[str],
) -> bool:
    """Return True if the matched text is almost certainly not a hostname."""
    return (
        _matches_allowlist(text, allowlist)
        or _looks_like_file_reference(text)
        or _looks_like_maven_property(text, line, match_end)
        or _inside_markup_anchor(line, match_start)
        or _looks_like_artifact_name(text)
    )
