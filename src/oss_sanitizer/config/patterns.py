"""Configuration dataclasses: LLMConfig, ScoringWeights, PatternsConfig."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LLMConfig:
    """LLM configuration. Supports OpenAI-compatible and Anthropic providers."""

    provider: str = "openai"  # "openai" or "anthropic"
    base_url: str = "http://localhost:11434/v1"
    api_key: str = "unused"
    model: str = "llama3"
    max_tokens: int = 1024
    temperature: float = 0.1


@dataclass
class ScoringWeights:
    """Weights for each finding category (higher = more severe)."""

    secret: float = 10.0
    internal_url: float = 7.0
    internal_hostname: float = 6.0
    sensitive_algorithm: float = 8.0


@dataclass
class PatternsConfig:
    """Configurable patterns for detection."""

    internal_url_domains: list[str] = field(
        default_factory=lambda: [
            r"\.etat-ge\.ch",
            r"\.ge\.ch",
            r"\.geneve\.ch",
            r"\.gva\.ch",
            r"\.admin\.ch",
        ]
    )

    # Hostname patterns (looks like internal infra).
    # Tier 1: always flag even without a dot (unambiguous infra names).
    # Tier 2: ambiguous prefixes — require a dot to suggest FQDN.
    hostname_patterns: list[str] = field(
        default_factory=lambda: [
            r"\b(?:srv|server|db|ldap|ad|dc|dns|mail|smtp|imap|ftp|nfs|nas|san|vpn|gw|fw|lb|mgmt|mon|bkp|nexus|sonar|jira|confluence)[-_][a-zA-Z0-9][-a-zA-Z0-9_.]*\b",
            r"\b(?:app|web|api|proxy|ci|cd|git|svn|jenkins|log)[-_][a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9.]+)\b",
            r"\b[a-zA-Z]{2,}[-_](?:prod|staging|stage|stg|preprod|recette|rct|qual|qualif|uat)\b",
            r"\b(?:prod|staging|stg|preprod|recette|rct)[-_][a-zA-Z][-a-zA-Z0-9]*\b",
            r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
        ]
    )

    hostname_allowlist: list[str] = field(
        default_factory=lambda: [
            "process-test-classes", "pre-integration-test", "post-integration-test",
            "test-compile", "generate-test-sources", "generate-test-resources",
            "process-test-resources", "test-jar", "integration-test", "verify",
            "-plugin", "-starter", "-autoconfigure",
        ]
    )

    skip_extensions: list[str] = field(
        default_factory=lambda: [
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
            ".woff", ".woff2", ".ttf", ".eot",
            ".zip", ".tar", ".gz", ".bz2", ".7z", ".jar", ".war", ".ear",
            ".class", ".pyc", ".pyo", ".so", ".dll", ".exe",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx",
            ".lock",
        ]
    )

    skip_paths: list[str] = field(
        default_factory=lambda: [
            ".git/",
            "node_modules/",
            "__pycache__/",
            ".venv/",
            "vendor/",
            ".gradle/",
            ".mvn/",
        ]
    )

    url_allowlist: list[str] = field(
        default_factory=lambda: [
            r"https?://(?:www\.)?github\.com",
            r"https?://(?:www\.)?opensource\.org",
            r"https?://(?:www\.)?creativecommons\.org",
            r"https?://(?:www\.)?apache\.org",
            r"https?://(?:www\.)?gnu\.org",
            r"https?://(?:www\.)?w3\.org",
            r"https?://(?:www\.)?xml\.org",
            r"https?://(?:www\.)?json-schema\.org",
            r"https?://schemas\.",
            r"https?://xmlns\.",
        ]
    )
