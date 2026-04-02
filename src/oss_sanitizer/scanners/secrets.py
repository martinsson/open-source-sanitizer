"""Secret detection scanner powered by detect-secrets plugins."""

from __future__ import annotations

import re
from functools import lru_cache

from detect_secrets.plugins.artifactory import ArtifactoryDetector
from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.plugins.azure_storage_key import AzureStorageKeyDetector
from detect_secrets.plugins.base import BasePlugin
from detect_secrets.plugins.basic_auth import BasicAuthDetector
from detect_secrets.plugins.github_token import GitHubTokenDetector
from detect_secrets.plugins.gitlab_token import GitLabTokenDetector
from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString, HexHighEntropyString
from detect_secrets.plugins.jwt import JwtTokenDetector
from detect_secrets.plugins.keyword import KeywordDetector
from detect_secrets.plugins.private_key import PrivateKeyDetector
from detect_secrets.plugins.slack import SlackDetector

from ..config import Config
from ..models import Finding, FindingType

# Files that commonly have false positives
FALSE_POSITIVE_PATHS = [
    r"(?:^|/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|go\.sum|poetry\.lock)$",
    r"(?:^|/)\.git/",
    r"(?:^|/)test(?:s|data|fixtures?)/.*(?:mock|fake|stub|fixture|sample|example)",
]


def is_false_positive_path(path: str) -> bool:
    return any(re.search(p, path) for p in FALSE_POSITIVE_PATHS)


@lru_cache(maxsize=1)
def _get_plugins() -> list[BasePlugin]:
    """Instantiate and cache all detect-secrets plugins."""
    return [
        AWSKeyDetector(),
        ArtifactoryDetector(),
        AzureStorageKeyDetector(),
        BasicAuthDetector(),
        GitHubTokenDetector(),
        GitLabTokenDetector(),
        JwtTokenDetector(),
        KeywordDetector(),
        PrivateKeyDetector(),
        SlackDetector(),
        Base64HighEntropyString(limit=4.5),
        HexHighEntropyString(limit=3.0),
    ]


def scan_for_secrets(
    content: str,
    file_path: str,
    config: Config,
    commit_sha: str | None = None,
) -> list[Finding]:
    """Scan file content for secrets using detect-secrets plugins."""
    if is_false_positive_path(file_path):
        return []

    lines = content.splitlines()
    plugins = _get_plugins()
    weight = config.scoring.secret / 10.0

    findings: list[Finding] = []
    seen_lines: set[int] = set()  # one finding per line

    for line_idx, line in enumerate(lines, start=1):
        if line_idx in seen_lines:
            continue

        for plugin in plugins:
            results = list(plugin.analyze_line(
                filename=file_path,
                line=line,
                line_number=line_idx,
            ))
            if not results:
                continue

            secret = results[0]
            secret_type = secret.type

            # Build snippet with masked secret value
            start = max(0, line_idx - 3)
            end = min(len(lines), line_idx + 2)
            snippet_lines = lines[start:end]
            snippet = "\n".join(
                f"{start + i + 1:>4} | {l}" for i, l in enumerate(snippet_lines)
            )

            # Mask the raw secret value in the snippet
            if secret.secret_value and len(secret.secret_value) > 8:
                masked = secret.secret_value[:4] + "..." + secret.secret_value[-4:]
                snippet = snippet.replace(secret.secret_value, masked)

            findings.append(
                Finding(
                    finding_type=FindingType.SECRET,
                    description=secret_type,
                    file_path=file_path,
                    line_number=line_idx,
                    score=10.0 * weight,  # all secrets get max weight (severity is binary)
                    snippet=snippet,
                    explanation=f"Pattern matched: {secret_type}. Secrets must be removed per Charte §2 (Confidentialité).",
                    commit_sha=commit_sha,
                )
            )
            seen_lines.add(line_idx)
            break  # one finding per line

    return findings
