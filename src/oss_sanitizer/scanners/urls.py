"""Internal URL and hostname detection scanner."""

from __future__ import annotations

from pathlib import Path

from ..config import Config
from ..models import Finding, FindingType
from .hostname_filters import is_false_positive_hostname
from .pom.model import parse as parse_pom_file, parse_from_text as parse_pom_text
from .url_utils import (
    URL_PATTERN,
    compile_patterns,
    hostname_explanation,
    is_pom_file,
    is_properties_file,
    make_snippet,
    url_explanation,
)


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
    allowlist = compile_patterns(config.patterns.url_allowlist)
    internal_domains = compile_patterns(config.patterns.internal_url_domains)
    hostname_patterns = compile_patterns(config.patterns.hostname_patterns)
    hostname_allowlist = config.patterns.hostname_allowlist

    # For pom.xml: use PomModel for context-aware per-line scoring.
    # For all other files (including generic XML): full score — no reduction.
    pom_model = None
    if is_pom_file(file_path):
        if repo_path:
            pom_model = parse_pom_file(Path(repo_path) / file_path, Path(repo_path))
        if pom_model is None:
            # Fallback: parse from in-memory content (tests, history scanning)
            pom_model = parse_pom_text(content, file_path)

    is_props = is_properties_file(file_path)

    for line_idx, line in enumerate(lines, start=1):
        # Skip comment lines in properties/config files
        if is_props and line.lstrip().startswith(("#", "!", "//")):
            continue

        # Determine context-based score factor (or skip).
        # pom.xml: delegate to PomModel for Maven-aware context scoring.
        # Everything else (including generic XML): full score.
        factor = pom_model.score_factor_for_line(line_idx) if pom_model else 1.0
        if factor is None:
            continue

        findings.extend(_scan_line_urls(line, line_idx, lines, allowlist, internal_domains, factor, config, file_path, commit_sha))
        findings.extend(_scan_line_hostnames(line, line_idx, lines, hostname_patterns, hostname_allowlist, factor, config, file_path, commit_sha))

    return findings


def _scan_line_urls(line, line_idx, lines, allowlist, internal_domains, factor, config, file_path, commit_sha):
    findings = []
    for url_match in URL_PATTERN.finditer(line):
        url = url_match.group(0)
        if any(a.search(url) for a in allowlist):
            continue
        if any(d.search(url) for d in internal_domains):
            findings.append(Finding(
                finding_type=FindingType.INTERNAL_URL,
                description=f"Internal URL: {url}",
                file_path=file_path,
                line_number=line_idx,
                score=config.scoring.internal_url * factor,
                snippet=make_snippet(lines, line_idx),
                explanation=url_explanation(factor),
                commit_sha=commit_sha,
            ))
    return findings


def _scan_line_hostnames(line, line_idx, lines, hostname_patterns, hostname_allowlist, factor, config, file_path, commit_sha):
    hostname_matches: list[tuple[int, int, str]] = []
    for hp in hostname_patterns:
        for hm in hp.finditer(line):
            hostname_matches.append((hm.start(), hm.end(), hm.group(0)))

    filtered = _filter_hostname_overlaps(hostname_matches)

    findings = []
    for start, end, hostname in filtered:
        if any(m.start() <= start and end <= m.end() for m in URL_PATTERN.finditer(line)):
            continue
        if is_false_positive_hostname(hostname, line, start, end, hostname_allowlist):
            continue
        findings.append(Finding(
            finding_type=FindingType.INTERNAL_HOSTNAME,
            description=f"Internal hostname: {hostname}",
            file_path=file_path,
            line_number=line_idx,
            score=config.scoring.internal_hostname * factor,
            snippet=make_snippet(lines, line_idx),
            explanation=hostname_explanation(factor),
            commit_sha=commit_sha,
        ))
    return findings


def _filter_hostname_overlaps(matches: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """Keep only longest match per position, no overlaps."""
    filtered = []
    seen_positions: set[tuple[int, str]] = set()
    for start, end, text in sorted(matches, key=lambda x: -(x[1] - x[0])):
        if (start, text) in seen_positions:
            continue
        if not any(s <= start and end <= e and (s, e) != (start, end) for s, e, _ in filtered):
            filtered.append((start, end, text))
            seen_positions.add((start, text))
    return filtered
