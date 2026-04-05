"""Secret detection scanner powered by detect-secrets plugins."""

from __future__ import annotations

import re
from dataclasses import dataclass
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

BASE64_ENTROPY_LIMIT = 4.5
HEX_ENTROPY_LIMIT = 3.0
MAX_SECRET_SCORE = 10.0
SECRET_WEIGHT_DENOMINATOR = 10

FALSE_POSITIVE_PATHS = [
    r"(?:^|/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|go\.sum|poetry\.lock)$",
    r"(?:^|/)\.git/",
    r"(?:^|/)test(?:s|data|fixtures?)/.*(?:mock|fake|stub|fixture|sample|example)",
]


@dataclass
class _SecretCtx:
    lines: list[str]
    file_path: str
    weight: float
    commit_sha: str | None


def is_false_positive_path(path: str) -> bool:
    return any(re.search(p, path) for p in FALSE_POSITIVE_PATHS)


@lru_cache(maxsize=1)
def _get_plugins() -> list[BasePlugin]:
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
        Base64HighEntropyString(limit=BASE64_ENTROPY_LIMIT),
        HexHighEntropyString(limit=HEX_ENTROPY_LIMIT),
    ]


def _build_secret_finding(secret, line_idx: int, ctx: _SecretCtx) -> Finding:
    start = max(0, line_idx - 3)
    end = min(len(ctx.lines), line_idx + 2)
    snippet = "\n".join(f"{start + i + 1:>4} | {l}" for i, l in enumerate(ctx.lines[start:end]))
    if secret.secret_value and len(secret.secret_value) > 8:
        masked = secret.secret_value[:4] + "..." + secret.secret_value[-4:]
        snippet = snippet.replace(secret.secret_value, masked)
    return Finding(
        finding_type=FindingType.SECRET,
        description=secret.type,
        file_path=ctx.file_path,
        line_number=line_idx,
        score=MAX_SECRET_SCORE * ctx.weight,
        snippet=snippet,
        explanation=f"Pattern matched: {secret.type}. Secrets must be removed per Charte §2 (Confidentialité).",
        commit_sha=ctx.commit_sha,
    )


def _scan_lines(ctx: _SecretCtx, plugins: list[BasePlugin]) -> list[Finding]:
    findings: list[Finding] = []
    seen_lines: set[int] = set()
    for line_idx, line in enumerate(ctx.lines, start=1):
        if line_idx in seen_lines:
            continue
        for plugin in plugins:
            results = list(plugin.analyze_line(filename=ctx.file_path, line=line, line_number=line_idx))
            if results:
                findings.append(_build_secret_finding(results[0], line_idx, ctx))
                seen_lines.add(line_idx)
                break
    return findings


def scan_for_secrets(
    content: str,
    file_path: str,
    config: Config,
    commit_sha: str | None = None,
) -> list[Finding]:
    """Scan file content for secrets using detect-secrets plugins."""
    if is_false_positive_path(file_path):
        return []
    ctx = _SecretCtx(
        lines=content.splitlines(),
        file_path=file_path,
        weight=config.scoring.secret / SECRET_WEIGHT_DENOMINATOR,
        commit_sha=commit_sha,
    )
    return _scan_lines(ctx, _get_plugins())
