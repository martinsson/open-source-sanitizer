"""Secret detection scanner using detect-secrets patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..config import Config
from ..models import Finding, FindingType

# Patterns inspired by detect-secrets and trufflehog
SECRET_PATTERNS: list[tuple[str, str, float]] = [
    # (pattern, description, base_score)

    # Private keys
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private key", 10.0),
    (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP private key", 10.0),

    # AWS
    (r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}", "AWS Access Key ID", 10.0),
    (r"(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}", "AWS Secret Key", 10.0),

    # Generic API keys/tokens
    (r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}", "API key", 9.0),
    (r"(?i)(?:access[_-]?token|auth[_-]?token|bearer[_-]?token)\s*[=:]\s*['\"]?[A-Za-z0-9_\-.]{16,}", "Access/auth token", 9.0),
    (r"(?i)(?:secret[_-]?key|client[_-]?secret|app[_-]?secret)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}", "Secret key", 9.0),

    # Passwords in config/code
    (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]", "Hardcoded password", 10.0),
    (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*[A-Za-z0-9_\-!@#$%^&*]{8,}", "Hardcoded password (unquoted)", 9.0),

    # Connection strings
    (r"(?i)(?:jdbc|mongodb|mysql|postgres|postgresql|redis|amqp|mssql|oracle):\/\/[^\s]+", "Database connection string", 9.0),
    (r"(?i)(?:Data Source|Server)\s*=\s*[^;\s]+;.*(?:Password|Pwd)\s*=\s*[^;\s]+", ".NET connection string with password", 10.0),

    # GitHub/GitLab tokens
    (r"gh[pousr]_[A-Za-z0-9_]{36,}", "GitHub token", 10.0),
    (r"glpat-[A-Za-z0-9_\-]{20,}", "GitLab token", 10.0),

    # Slack
    (r"xox[baprs]-[0-9]{10,}-[0-9A-Za-z\-]+", "Slack token", 9.0),

    # Generic high-entropy strings in assignments (catch-all)
    (r"(?i)(?:token|secret|credential|auth)\s*[=:]\s*['\"][A-Za-z0-9+/=_\-]{32,}['\"]", "Generic secret in assignment", 8.0),
]

# Files that commonly have false positives
FALSE_POSITIVE_PATHS = [
    r"(?:^|/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|go\.sum|poetry\.lock)$",
    r"(?:^|/)\.git/",
    r"(?:^|/)test(?:s|data|fixtures?)/.*(?:mock|fake|stub|fixture|sample|example)",
]


@dataclass
class CompiledPattern:
    regex: re.Pattern
    description: str
    base_score: float


def compile_patterns() -> list[CompiledPattern]:
    return [
        CompiledPattern(re.compile(p), desc, score)
        for p, desc, score in SECRET_PATTERNS
    ]


_compiled: list[CompiledPattern] | None = None


def get_patterns() -> list[CompiledPattern]:
    global _compiled
    if _compiled is None:
        _compiled = compile_patterns()
    return _compiled


def is_false_positive_path(path: str) -> bool:
    return any(re.search(p, path) for p in FALSE_POSITIVE_PATHS)


def scan_content(
    content: str,
    file_path: str,
    config: Config,
    commit_sha: str | None = None,
) -> list[Finding]:
    """Scan file content for secrets."""
    if is_false_positive_path(file_path):
        return []

    findings: list[Finding] = []
    lines = content.splitlines()
    patterns = get_patterns()

    for line_idx, line in enumerate(lines, start=1):
        for pat in patterns:
            match = pat.regex.search(line)
            if not match:
                continue

            # Build a snippet: 2 lines before and after
            start = max(0, line_idx - 3)
            end = min(len(lines), line_idx + 2)
            snippet_lines = lines[start:end]
            snippet = "\n".join(
                f"{start + i + 1:>4} | {l}" for i, l in enumerate(snippet_lines)
            )

            # Mask the actual secret in the snippet
            matched_text = match.group(0)
            if len(matched_text) > 8:
                masked = matched_text[:4] + "..." + matched_text[-4:]
            else:
                masked = matched_text[:2] + "..."
            snippet = snippet.replace(matched_text, masked)

            findings.append(
                Finding(
                    finding_type=FindingType.SECRET,
                    description=pat.description,
                    file_path=file_path,
                    line_number=line_idx,
                    score=pat.base_score * config.scoring.secret / 10.0,
                    snippet=snippet,
                    explanation=f"Pattern matched: {pat.description}. Secrets must be removed per Charte §2 (Confidentialité).",
                    commit_sha=commit_sha,
                )
            )
            break  # one finding per line

    return findings
