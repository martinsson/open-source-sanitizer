"""Tests for the configuration module."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from oss_sanitizer.config import Config, LLMConfig, ScoringWeights, PatternsConfig


def test_default_config():
    config = Config()
    assert config.llm.provider == "openai"
    assert config.scoring.secret == 10.0
    assert config.max_file_size_kb == 512
    assert len(config.patterns.internal_url_domains) >= 4
    assert len(config.patterns.hostname_patterns) >= 3


def test_from_yaml_merges_with_defaults():
    data = {
        "scoring": {"secret": 5.0},
        "max_file_size_kb": 1024,
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        f.flush()
        config = Config.from_yaml(Path(f.name))

    assert config.scoring.secret == 5.0
    assert config.scoring.internal_url == 7.0  # default preserved
    assert config.max_file_size_kb == 1024


def test_from_yaml_llm_config():
    data = {
        "llm": {
            "provider": "anthropic",
            "model": "claude-sonnet-4-6",
            "api_key": "test-key",
        }
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        f.flush()
        config = Config.from_yaml(Path(f.name))

    assert config.llm.provider == "anthropic"
    assert config.llm.model == "claude-sonnet-4-6"
    assert config.llm.api_key == "test-key"
    assert config.llm.base_url == "http://localhost:11434/v1"  # default preserved


def test_from_yaml_handles_bom():
    """YAML files with UTF-8 BOM should be handled (M5 fix)."""
    data = {"scoring": {"secret": 3.0}}
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".yaml", delete=False) as f:
        # Write BOM + YAML content
        f.write(b"\xef\xbb\xbf")
        f.write(yaml.dump(data).encode("utf-8"))
        f.flush()
        config = Config.from_yaml(Path(f.name))

    assert config.scoring.secret == 3.0


def test_from_yaml_empty_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("")
        f.flush()
        config = Config.from_yaml(Path(f.name))

    # Should return defaults
    assert config.scoring.secret == 10.0


def test_load_allowlist():
    data = {
        "public_websites": ["example.com", "public.ge.ch"],
        "other": ["test.org"],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        f.flush()

        config = Config()
        original_count = len(config.patterns.url_allowlist)
        config.load_allowlist(Path(f.name))

    assert len(config.patterns.url_allowlist) == original_count + 3


def test_load_allowlist_nonexistent():
    config = Config()
    original_count = len(config.patterns.url_allowlist)
    config.load_allowlist(Path("/nonexistent/allowlist.yaml"))
    assert len(config.patterns.url_allowlist) == original_count


def test_load_blacklist():
    data = {
        "internal_url_domains": [r"\.secret\.internal"],
        "hostname_patterns": [r"\bsecret-server\b"],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        f.flush()

        config = Config()
        config.load_blacklist(Path(f.name))

    assert r"\.secret\.internal" in config.patterns.internal_url_domains
    assert r"\bsecret-server\b" in config.patterns.hostname_patterns


def test_load_blacklist_no_duplicates():
    data = {
        "internal_url_domains": [r"\.etat-ge\.ch"],  # already in defaults
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(data, f)
        f.flush()

        config = Config()
        count_before = len(config.patterns.internal_url_domains)
        config.load_blacklist(Path(f.name))

    assert len(config.patterns.internal_url_domains) == count_before


def test_load_blacklist_nonexistent():
    config = Config()
    original = len(config.patterns.hostname_patterns)
    config.load_blacklist(Path("/nonexistent/blacklist.yaml"))
    assert len(config.patterns.hostname_patterns) == original
