"""Config class — loads, merges, and validates oss-sanitizer configuration."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .patterns import LLMConfig, PatternsConfig, ScoringWeights

logger = logging.getLogger(__name__)


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
        with open(path, encoding="utf-8-sig") as f:
            data = yaml.safe_load(f) or {}
        config = cls()
        _apply_yaml_overrides(config, data)
        return config

    def load_allowlist(self, path: Path) -> None:
        """Load public domains allowlist YAML and add to url_allowlist patterns."""
        if not path.exists():
            return
        with open(path, encoding="utf-8-sig") as f:
            data = yaml.safe_load(f) or {}
        domains = [entry for group in data.values() if isinstance(group, list) for entry in group]
        for domain in domains:
            self.patterns.url_allowlist.append(rf"https?://(?:www\.)?{re.escape(domain)}")
        logger.info(f"Loaded {len(domains)} allowlisted domains from {path}")

    def load_blacklist(self, path: Path) -> None:
        """Load internal domains blacklist YAML and add to detection patterns."""
        if not path.exists():
            logger.debug(f"No blacklist file at {path}")
            return
        with open(path, encoding="utf-8-sig") as f:
            data = yaml.safe_load(f) or {}
        _merge_no_dup(self.patterns.internal_url_domains, data.get("internal_url_domains", []))
        _merge_no_dup(self.patterns.hostname_patterns, data.get("hostname_patterns", []))
        _merge_no_dup(self.patterns.hostname_allowlist, data.get("hostname_allowlist", []))
        logger.info(f"Loaded blacklist from {path}")


def _merge_section(obj, updates: dict, section: str) -> None:
    valid = {f.name for f in obj.__dataclass_fields__.values()}
    for k, v in updates.items():
        if k not in valid:
            raise ValueError(f"Unknown config key [{section}].{k!r}. Valid keys: {sorted(valid)}")
        setattr(obj, k, v)


def _apply_yaml_overrides(config: Config, data: dict) -> None:
    if "llm" in data:
        _merge_section(config.llm, data["llm"], "llm")
    if "scoring" in data:
        _merge_section(config.scoring, data["scoring"], "scoring")
    if "patterns" in data:
        _merge_section(config.patterns, data["patterns"], "patterns")
    if "scan_history" in data:
        config.scan_history = data["scan_history"]
    if "max_file_size_kb" in data:
        config.max_file_size_kb = data["max_file_size_kb"]


def _merge_no_dup(target: list, source: list) -> None:
    for item in source:
        if item not in target:
            target.append(item)
