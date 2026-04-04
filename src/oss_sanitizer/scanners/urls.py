"""Internal URL and hostname detection scanner."""

from __future__ import annotations

import os
import re
from pathlib import Path  # needed for parse_pom_file call

from ..config import Config
from ..models import Finding, FindingType
from .hostname_filters import is_false_positive_hostname
from .pom.model import parse as parse_pom_file, parse_from_text as parse_pom_text

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
            if is_false_positive_hostname(hostname, line, start, end, hostname_allowlist):
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
