"""Configuration for oss-sanitizer."""

from __future__ import annotations

import logging
import re

import yaml
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


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

    # Internal URL patterns
    internal_url_domains: list[str] = field(
        default_factory=lambda: [
            r"\.etat-ge\.ch",
            r"\.ge\.ch",
            r"\.geneve\.ch",
            r"\.gva\.ch",
            r"\.admin\.ch",
        ]
    )

    # Hostname patterns (looks like internal infra)
    hostname_patterns: list[str] = field(
        default_factory=lambda: [
            r"\b(?:srv|server|db|app|web|api|proxy|ldap|ad|dc|dns|mail|smtp|imap|ftp|nfs|nas|san|vpn|gw|fw|lb|mgmt|mon|log|bkp|ci|cd|git|svn|jenkins|nexus|sonar|jira|confluence)[-_][a-zA-Z0-9][-a-zA-Z0-9_.]*\b",
            r"\b[a-zA-Z]+-(?:prod|staging|stage|stg|dev|test|uat|preprod|int|recette|rct|qual|qualif)\b",
            r"\b(?:prod|staging|dev|test|uat|preprod|int|recette|rct)-[a-zA-Z][-a-zA-Z0-9]*\b",
            r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
        ]
    )

    # File extensions to skip (binary, images, etc.)
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

    # Paths to skip
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

    # Allowlisted URLs (won't be flagged)
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


@dataclass
class Config:
    """Top-level configuration."""

    llm: LLMConfig = field(default_factory=LLMConfig)
    scoring: ScoringWeights = field(default_factory=ScoringWeights)
    patterns: PatternsConfig = field(default_factory=PatternsConfig)
    scan_history: bool = False
    max_file_size_kb: int = 512

    @classmethod
    def from_yaml(cls, path: Path) -> Config:
        """Load config from a YAML file, merging with defaults."""
        with open(path) as f:
            data = yaml.safe_load(f) or {}

        config = cls()
        if "llm" in data:
            for k, v in data["llm"].items():
                setattr(config.llm, k, v)
        if "scoring" in data:
            for k, v in data["scoring"].items():
                setattr(config.scoring, k, v)
        if "patterns" in data:
            for k, v in data["patterns"].items():
                setattr(config.patterns, k, v)
        if "scan_history" in data:
            config.scan_history = data["scan_history"]
        if "max_file_size_kb" in data:
            config.max_file_size_kb = data["max_file_size_kb"]

        return config

    def load_allowlist(self, path: Path) -> None:
        """Load public domains allowlist YAML and add to url_allowlist patterns."""
        if not path.exists():
            return

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        domains: list[str] = []
        for group in data.values():
            if isinstance(group, list):
                for entry in group:
                    domains.append(entry)

        # Convert domain entries to regex patterns for URL matching
        for domain in domains:
            # Escape dots for regex, allow optional protocol prefix
            escaped = re.escape(domain)
            pattern = rf"https?://(?:www\.)?{escaped}"
            self.patterns.url_allowlist.append(pattern)

        logger.info(f"Loaded {len(domains)} allowlisted domains from {path}")

    def load_blacklist(self, path: Path) -> None:
        """Load internal domains blacklist YAML and add to detection patterns."""
        if not path.exists():
            logger.debug(f"No blacklist file at {path}")
            return

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        if "internal_url_domains" in data:
            for pattern in data["internal_url_domains"]:
                if pattern not in self.patterns.internal_url_domains:
                    self.patterns.internal_url_domains.append(pattern)

        if "hostname_patterns" in data:
            for pattern in data["hostname_patterns"]:
                if pattern not in self.patterns.hostname_patterns:
                    self.patterns.hostname_patterns.append(pattern)

        logger.info(f"Loaded blacklist from {path}")
