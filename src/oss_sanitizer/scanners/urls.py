"""Internal URL and hostname detection scanner."""

from __future__ import annotations

import os
import re
from pathlib import Path  # needed for parse_pom_file call

import tldextract

from ..config import Config
from ..models import Finding, FindingType
from .pom_model import parse as parse_pom_file, parse_from_text as parse_pom_text

# General URL pattern
URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9][-a-zA-Z0-9_.]*(?::\d+)?(?:/[^\s'\")><\]]*)?",
)


def _is_pom_file(file_path: str) -> bool:
    """Only pom.xml files get Maven-aware context scoring."""
    return os.path.basename(file_path).lower() == "pom.xml"


# ── Properties file context ────────────────────────────────────────────

_PROPERTIES_EXTS = {".properties", ".cfg", ".ini", ".env", ".conf"}


def _is_properties_file(file_path: str) -> bool:
    ext = os.path.splitext(file_path)[1].lower()
    base = os.path.basename(file_path).lower()
    if ext in _PROPERTIES_EXTS:
        return True
    if base in (".env", "application.yml", "application.yaml",
                "application.properties", "bootstrap.yml", "bootstrap.yaml"):
        return True
    return False


# ── Hostname false-positive filters ───────────────────────────────────

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


_ARTIFACT_KEYWORDS = frozenset({
    "test", "plugin", "starter", "autoconfigure", "connector", "adapter",
    "helper", "util", "utils", "commons", "core", "api", "impl", "mock", "stub",
})


def _looks_like_artifact_name(text: str) -> bool:
    """A dotted match whose TLD is public and whose domain looks like a library name."""
    if "." not in text:
        return False
    extracted = tldextract.extract(text)
    suffix = extracted.suffix.lower() if extracted.suffix else ""
    domain = extracted.domain.lower() if extracted.domain else ""

    # Internal TLD — definitely a hostname, not an artifact
    if suffix in _INTERNAL_TLDS:
        return False

    if suffix:
        if domain in _ARTIFACT_KEYWORDS:
            return True
        if any(domain.endswith(f"-{k}") or domain.startswith(f"{k}-")
               for k in _ARTIFACT_KEYWORDS):
            return True

    return False


def _is_false_positive_hostname(text: str, line: str, match_start: int, match_end: int, allowlist: list[str]) -> bool:
    """Return True if the matched text is almost certainly not a hostname."""
    return (
        _matches_allowlist(text, allowlist)
        or _looks_like_file_reference(text)
        or _looks_like_maven_property(text, line, match_end)
        or _inside_markup_anchor(line, match_start)
        or _looks_like_artifact_name(text)
    )


# ── Compiled pattern cache ─────────────────────────────────────────────
#
# Patterns are derived from Config, which doesn't change during a scan.
# Compiling once and reusing avoids re-creating regex objects per file.

_pattern_cache: dict[tuple, list[re.Pattern]] = {}


def _compile_patterns(raw: list[str]) -> list[re.Pattern]:
    key = tuple(raw)
    if key not in _pattern_cache:
        _pattern_cache[key] = [re.compile(p) for p in raw]
    return _pattern_cache[key]


def _make_snippet(lines: list[str], line_idx: int) -> str:
    start = max(0, line_idx - 3)
    end = min(len(lines), line_idx + 2)
    snippet_lines = lines[start:end]
    return "\n".join(
        f"{start + i + 1:>4} | {l}" for i, l in enumerate(snippet_lines)
    )


# ── Main scanner ───────────────────────────────────────────────────────

def scan_for_internal_references(
    content: str,
    file_path: str,
    config: Config,
    commit_sha: str | None = None,
    repo_path: str | None = None,
) -> list[Finding]:
    """Scan for internal URLs and hostnames."""
    findings: list[Finding] = []
    lines = content.splitlines()
    allowlist = _compile_patterns(config.patterns.url_allowlist)
    internal_domains = _compile_patterns(config.patterns.internal_url_domains)
    hostname_patterns = _compile_patterns(config.patterns.hostname_patterns)
    hostname_allowlist = config.patterns.hostname_allowlist

    # For pom.xml: use PomModel for context-aware per-line scoring.
    # For all other files (including generic XML): full score — no reduction.
    pom_model = None
    if _is_pom_file(file_path):
        if repo_path:
            pom_model = parse_pom_file(Path(repo_path) / file_path, Path(repo_path))
        if pom_model is None:
            # Fallback: parse from in-memory content (tests, history scanning)
            pom_model = parse_pom_text(content, file_path)

    is_props = _is_properties_file(file_path)

    for line_idx, line in enumerate(lines, start=1):
        # Skip comment lines in properties/config files
        if is_props and line.lstrip().startswith(("#", "!", "//")):
            continue

        # Determine context-based score factor (or skip).
        # pom.xml: delegate to PomModel for Maven-aware context scoring.
        # Everything else (including generic XML): full score.
        if pom_model is not None:
            factor = pom_model.score_factor_for_line(line_idx)
        else:
            factor = 1.0

        if factor is None:
            continue

        # --- Internal URL detection ---
        for url_match in URL_PATTERN.finditer(line):
            url = url_match.group(0)

            if any(a.search(url) for a in allowlist):
                continue

            if any(d.search(url) for d in internal_domains):
                score = config.scoring.internal_url * factor
                findings.append(
                    Finding(
                        finding_type=FindingType.INTERNAL_URL,
                        description=f"Internal URL: {url}",
                        file_path=file_path,
                        line_number=line_idx,
                        score=score,
                        snippet=_make_snippet(lines, line_idx),
                        explanation=_url_explanation(factor),
                        commit_sha=commit_sha,
                    )
                )

        # --- Internal hostname detection ---
        hostname_matches: list[tuple[int, int, str]] = []
        for hp in hostname_patterns:
            for hm in hp.finditer(line):
                hostname_matches.append((hm.start(), hm.end(), hm.group(0)))

        # Keep only longest match per position (no overlaps), deduplicate
        filtered = []
        seen_positions: set[tuple[int, str]] = set()
        for start, end, text in sorted(hostname_matches, key=lambda x: -(x[1] - x[0])):
            if (start, text) in seen_positions:
                continue
            if not any(s <= start and end <= e and (s, e) != (start, end) for s, e, _ in filtered):
                filtered.append((start, end, text))
                seen_positions.add((start, text))

        for start, end, hostname in filtered:
            # Skip if inside a URL already flagged
            if any(m.start() <= start and end <= m.end() for m in URL_PATTERN.finditer(line)):
                continue

            # Apply false-positive filters
            if _is_false_positive_hostname(hostname, line, start, end, hostname_allowlist):
                continue

            score = config.scoring.internal_hostname * factor
            findings.append(
                Finding(
                    finding_type=FindingType.INTERNAL_HOSTNAME,
                    description=f"Internal hostname: {hostname}",
                    file_path=file_path,
                    line_number=line_idx,
                    score=score,
                    snippet=_make_snippet(lines, line_idx),
                    explanation=_hostname_explanation(factor),
                    commit_sha=commit_sha,
                )
            )

    return findings


def _url_explanation(factor: float) -> str:
    base = "Internal URLs must be removed before publication per Charte §2 (Confidentialité)."
    if factor < 1.0:
        base += f" (reduced confidence — score factor {factor:.0%} based on XML context)"
    return base


def _hostname_explanation(factor: float) -> str:
    base = "Internal hostnames/server names must be removed per Charte §2 (Confidentialité)."
    if factor < 1.0:
        base += f" (reduced confidence — score factor {factor:.0%} based on XML context)"
    return base
