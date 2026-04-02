"""Shared fixtures for tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_sanitizer.config import Config

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def config() -> Config:
    """Default Config with no allowlist/blacklist loaded."""
    return Config()


@pytest.fixture
def config_no_llm() -> Config:
    """Config with LLM disabled."""
    c = Config()
    c.scoring.sensitive_algorithm = 0.0
    return c
