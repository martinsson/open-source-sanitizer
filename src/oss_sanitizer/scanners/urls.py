"""Internal URL and hostname detection scanner."""

from __future__ import annotations

import re

from ..config import Config
from ..models import Finding, FindingType

# General URL pattern
URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9][-a-zA-Z0-9_.]*(?::\d+)?(?:/[^\s'\")>\]]*)?",
)


def _build_allowlist(config: Config) -> list[re.Pattern]:
    return [re.compile(p) for p in config.patterns.url_allowlist]


def _build_internal_domain_patterns(config: Config) -> list[re.Pattern]:
    return [re.compile(p) for p in config.patterns.internal_url_domains]


def _build_hostname_patterns(config: Config) -> list[re.Pattern]:
    return [re.compile(p) for p in config.patterns.hostname_patterns]


def _make_snippet(lines: list[str], line_idx: int) -> str:
    start = max(0, line_idx - 3)
    end = min(len(lines), line_idx + 2)
    snippet_lines = lines[start:end]
    return "\n".join(
        f"{start + i + 1:>4} | {l}" for i, l in enumerate(snippet_lines)
    )


def scan_content(
    content: str,
    file_path: str,
    config: Config,
    commit_sha: str | None = None,
) -> list[Finding]:
    """Scan for internal URLs and hostnames."""
    findings: list[Finding] = []
    lines = content.splitlines()
    allowlist = _build_allowlist(config)
    internal_domains = _build_internal_domain_patterns(config)
    hostname_patterns = _build_hostname_patterns(config)

    for line_idx, line in enumerate(lines, start=1):
        # --- Internal URL detection ---
        for url_match in URL_PATTERN.finditer(line):
            url = url_match.group(0)

            # Skip allowlisted URLs
            if any(a.search(url) for a in allowlist):
                continue

            # Check if it matches an internal domain
            if any(d.search(url) for d in internal_domains):
                findings.append(
                    Finding(
                        finding_type=FindingType.INTERNAL_URL,
                        description=f"Internal URL: {url}",
                        file_path=file_path,
                        line_number=line_idx,
                        score=config.scoring.internal_url,
                        snippet=_make_snippet(lines, line_idx),
                        explanation="Internal URLs must be removed before publication per Charte §2 (Confidentialité).",
                        commit_sha=commit_sha,
                    )
                )

        # --- Internal hostname detection ---
        # Collect all hostname matches, then keep only the longest per position
        hostname_matches: list[tuple[int, int, str]] = []  # (start, end, text)
        for hp in hostname_patterns:
            for hm in hp.finditer(line):
                hostname_matches.append((hm.start(), hm.end(), hm.group(0)))

        # Remove matches that are substrings of longer matches
        filtered = []
        for start, end, text in sorted(hostname_matches, key=lambda x: -(x[1] - x[0])):
            if not any(s <= start and end <= e and (s, e) != (start, end) for s, e, _ in filtered):
                filtered.append((start, end, text))

        for start, end, hostname in filtered:
            # Skip if it's inside a URL we already flagged
            inside_url = False
            for url_match in URL_PATTERN.finditer(line):
                if url_match.start() <= start and end <= url_match.end():
                    inside_url = True
                    break
            if inside_url:
                continue

            findings.append(
                Finding(
                    finding_type=FindingType.INTERNAL_HOSTNAME,
                    description=f"Internal hostname: {hostname}",
                    file_path=file_path,
                    line_number=line_idx,
                    score=config.scoring.internal_hostname,
                    snippet=_make_snippet(lines, line_idx),
                    explanation="Internal hostnames/server names must be removed per Charte §2 (Confidentialité).",
                    commit_sha=commit_sha,
                )
            )

    return findings
