"""Internal URL and hostname detection scanner."""

from __future__ import annotations

import os
import re

from ..config import Config
from ..models import Finding, FindingType

# General URL pattern
URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9][-a-zA-Z0-9_.]*(?::\d+)?(?:/[^\s'\")>\]]*)?",
)

# ── XML context scoring ────────────────────────────────────────────────
# For POM / XML files we detect which XML element a line belongs to and
# adjust the score accordingly.  Some elements (like <dependency>) almost
# never contain real infrastructure references while others (<properties>,
# <url>, <repository>, plugin <configuration>) very often do.

# Tags whose *content lines* should be completely ignored for hostname /
# URL scanning (Maven coordinates are not hostnames).
_XML_SKIP_TAGS = re.compile(
    r"<\s*(?:groupId|artifactId|version|packaging|modelVersion|module"
    r"|scope|type|classifier|systemPath|relativePath)\s*>"
)

# Tags where a finding is highly credible → full score
_XML_HIGH_TAGS = re.compile(
    r"<\s*(?:url|connection|developerConnection|downloadUrl"
    r"|snapshotRepository|repository|distributionManagement"
    r"|wsdlLocation|endpoint|baseUrl|serverUrl|host|address)\s*>"
)

# Tags where a finding is plausible → medium score
_XML_MEDIUM_TAGS = re.compile(
    r"<\s*(?:properties|configuration|param|value|setting"
    r"|property|arg|jvmArg|systemProperty|environment)\s*>"
)

# Anything else in an XML file gets a reduced score
_XML_DEFAULT_FACTOR = 0.5
_XML_MEDIUM_FACTOR = 0.8
_XML_HIGH_FACTOR = 1.0


def _is_xml_file(file_path: str) -> bool:
    ext = os.path.splitext(file_path)[1].lower()
    return ext in (".xml", ".pom", ".xsd", ".xsl", ".xslt", ".wsdl")


def _build_xml_score_map(content: str) -> list[float | None]:
    """Pre-compute a score factor for each line in an XML file.

    Tracks nesting to determine context: lines inside <dependency> blocks
    are skipped, lines inside <properties> or <configuration> get medium
    score, lines inside <url>/<repository> etc. get full score.
    """
    lines = content.splitlines()
    factors: list[float | None] = []

    # Simple stack-based parent tracking
    parent_stack: list[str] = []
    # Tags that open a "skip" context
    skip_parents = {"dependency", "dependencies", "parent", "exclusion", "exclusions"}
    # Tags that open a "high confidence" context
    high_parents = {"repository", "snapshotRepository", "pluginRepository",
                    "distributionManagement", "scm", "ciManagement",
                    "issueManagement", "mailingList"}
    # Tags that open a "medium confidence" context
    medium_parents = {"properties", "configuration", "profile", "build",
                      "plugins", "plugin", "execution"}

    open_tag = re.compile(r"<\s*([a-zA-Z][\w.-]*)\s*[^/]*?>")
    close_tag = re.compile(r"</\s*([a-zA-Z][\w.-]*)\s*>")
    self_closing = re.compile(r"<\s*([a-zA-Z][\w.-]*)\s*[^>]*/\s*>")

    for line in lines:
        stripped = line.strip()

        # Skip lines that are clearly Maven coordinate leaf tags
        if _XML_SKIP_TAGS.search(stripped):
            factors.append(None)
        else:
            # Determine factor from parent context
            factor = _XML_DEFAULT_FACTOR
            for parent in reversed(parent_stack):
                if parent in skip_parents:
                    factor = None
                    break
                if parent in high_parents:
                    factor = _XML_HIGH_FACTOR
                    break
                if parent in medium_parents:
                    factor = _XML_MEDIUM_FACTOR
                    break
            # Direct high-confidence tags on this line override
            if factor is not None and _XML_HIGH_TAGS.search(stripped):
                factor = _XML_HIGH_FACTOR
            factors.append(factor)

        # Update stack (after scoring this line)
        # Handle self-closing tags (no stack change)
        if self_closing.search(stripped):
            pass
        else:
            for m in open_tag.finditer(stripped):
                parent_stack.append(m.group(1))
            for m in close_tag.finditer(stripped):
                tag = m.group(1)
                # Pop up to the matching open tag
                while parent_stack and parent_stack[-1] != tag:
                    parent_stack.pop()
                if parent_stack:
                    parent_stack.pop()

    return factors


# ── Properties file context ────────────────────────────────────────────
# .properties / .cfg / .ini / .env / application.yml etc. — anything that
# looks like a key=value config is high confidence.

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


# ── Helpers ────────────────────────────────────────────────────────────

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


# ── Main scanner ───────────────────────────────────────────────────────

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

    # Pre-compute per-line score factors for XML files
    xml_factors: list[float | None] | None = None
    if _is_xml_file(file_path):
        xml_factors = _build_xml_score_map(content)

    for line_idx, line in enumerate(lines, start=1):
        # Determine context-based score factor (or skip)
        if xml_factors is not None:
            factor = xml_factors[line_idx - 1] if line_idx - 1 < len(xml_factors) else _XML_DEFAULT_FACTOR
        elif _is_properties_file(file_path):
            factor = 1.0
        else:
            factor = 1.0

        if factor is None:
            continue

        # --- Internal URL detection ---
        for url_match in URL_PATTERN.finditer(line):
            url = url_match.group(0)

            # Skip allowlisted URLs
            if any(a.search(url) for a in allowlist):
                continue

            # Check if it matches an internal domain
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
