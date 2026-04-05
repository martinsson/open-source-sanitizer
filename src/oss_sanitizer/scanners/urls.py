"""Internal URL and hostname detection scanner."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..config import Config
from ..models import Finding, FindingType
from .hostname_filters import HostnameMatch, is_false_positive_hostname
from .pom.model import PomModel, parse_from_text as parse_pom_text
from .url_utils import (
    URL_PATTERN,
    compile_patterns,
    hostname_explanation,
    is_pom_file,
    is_properties_file,
    make_snippet,
    url_explanation,
)


@dataclass
class _ScanContext:
    lines: list[str]
    config: Config
    file_path: str
    commit_sha: str | None
    allowlist: list[re.Pattern] = field(default_factory=list)
    internal_domains: list[re.Pattern] = field(default_factory=list)
    hostname_patterns: list[re.Pattern] = field(default_factory=list)
    hostname_allowlist: list[str] = field(default_factory=list)
    pom_model: PomModel | None = None
    is_props: bool = False


def scan_for_internal_references(
    content: str,
    file_path: str,
    config: Config,
    commit_sha: str | None = None,
) -> list[Finding]:
    """Scan for internal URLs and hostnames."""
    pom_model = parse_pom_text(content, file_path) if is_pom_file(file_path) else None
    ctx = _ScanContext(
        lines=content.splitlines(),
        config=config,
        file_path=file_path,
        commit_sha=commit_sha,
        allowlist=compile_patterns(config.patterns.url_allowlist),
        internal_domains=compile_patterns(config.patterns.internal_url_domains),
        hostname_patterns=compile_patterns(config.patterns.hostname_patterns),
        hostname_allowlist=config.patterns.hostname_allowlist,
        pom_model=pom_model,
        is_props=is_properties_file(file_path),
    )

    findings: list[Finding] = []
    for line_idx, line in enumerate(ctx.lines, start=1):
        if ctx.is_props and line.lstrip().startswith(("#", "!", "//")):
            continue
        factor = ctx.pom_model.score_factor_for_line(line_idx) if ctx.pom_model else 1.0
        if factor is None:
            continue
        findings.extend(_scan_line_urls(line, line_idx, ctx, factor))
        findings.extend(_scan_line_hostnames(line, line_idx, ctx, factor))
    return findings


def _scan_line_urls(line: str, line_idx: int, ctx: _ScanContext, factor: float) -> list[Finding]:
    findings = []
    for url_match in URL_PATTERN.finditer(line):
        url = url_match.group(0)
        if any(a.search(url) for a in ctx.allowlist):
            continue
        if any(d.search(url) for d in ctx.internal_domains):
            findings.append(Finding(
                finding_type=FindingType.INTERNAL_URL,
                description=f"Internal URL: {url}",
                file_path=ctx.file_path,
                line_number=line_idx,
                score=ctx.config.scoring.internal_url * factor,
                snippet=make_snippet(ctx.lines, line_idx),
                explanation=url_explanation(factor),
                commit_sha=ctx.commit_sha,
            ))
    return findings


def _without_url_overlaps(
    matches: list[tuple[int, int, str]], line: str,
) -> list[tuple[int, int, str]]:
    url_spans = [(m.start(), m.end()) for m in URL_PATTERN.finditer(line)]
    return [
        (start, end, h)
        for start, end, h in _filter_hostname_overlaps(matches)
        if not any(us <= start and end <= ue for us, ue in url_spans)
    ]


def _scan_line_hostnames(line: str, line_idx: int, ctx: _ScanContext, factor: float) -> list[Finding]:
    raw_matches: list[tuple[int, int, str]] = [
        (hm.start(), hm.end(), hm.group(0))
        for hp in ctx.hostname_patterns
        for hm in hp.finditer(line)
    ]
    findings = []
    for start, end, hostname in _without_url_overlaps(raw_matches, line):
        if is_false_positive_hostname(HostnameMatch(hostname, line, start, end, ctx.hostname_allowlist)):
            continue
        findings.append(Finding(
            finding_type=FindingType.INTERNAL_HOSTNAME,
            description=f"Internal hostname: {hostname}",
            file_path=ctx.file_path,
            line_number=line_idx,
            score=ctx.config.scoring.internal_hostname * factor,
            snippet=make_snippet(ctx.lines, line_idx),
            explanation=hostname_explanation(factor),
            commit_sha=ctx.commit_sha,
        ))
    return findings


def _filter_hostname_overlaps(matches: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """Keep only longest match per position, no overlaps."""
    filtered: list[tuple[int, int, str]] = []
    seen: set[tuple[int, str]] = set()
    for start, end, text in sorted(matches, key=lambda x: -(x[1] - x[0])):
        if (start, text) in seen:
            continue
        if not any(s <= start and end <= e and (s, e) != (start, end) for s, e, _ in filtered):
            filtered.append((start, end, text))
            seen.add((start, text))
    return filtered
