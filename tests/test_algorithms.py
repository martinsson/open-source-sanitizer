"""Tests for the LLM-based algorithm scanner."""

from __future__ import annotations

from unittest.mock import patch

from oss_sanitizer.config import Config
from oss_sanitizer.models import FindingType
from oss_sanitizer.scanners.algorithms import scan_for_sensitive_algorithms as scan_content


def test_skipped_when_score_zero():
    config = Config()
    config.scoring.sensitive_algorithm = 0.0
    findings = scan_content("def calculate_tax(): pass\n" * 20, "tax.py", config)
    assert findings == []


def test_skipped_for_short_files():
    config = Config()
    findings = scan_content("x = 1\n", "short.py", config)
    assert findings == []


def test_skipped_for_build_files():
    config = Config()
    content = "line\n" * 20
    for name in ["pom.xml", "package.json", "Dockerfile", "Makefile"]:
        findings = scan_content(content, name, config)
        assert findings == [], f"Should skip {name}"


@patch("oss_sanitizer.scanners.algorithms._call_llm")
def test_not_sensitive(mock_llm):
    mock_llm.return_value = {
        "is_sensitive": False,
        "confidence": 0.1,
        "explanation": "Generic utility code",
        "sensitive_sections": [],
    }
    config = Config()
    content = "def helper():\n    pass\n" * 10
    findings = scan_content(content, "utils.py", config)
    assert findings == []


@patch("oss_sanitizer.scanners.algorithms._call_llm")
def test_sensitive_with_sections(mock_llm):
    mock_llm.return_value = {
        "is_sensitive": True,
        "confidence": 0.85,
        "explanation": "Tax calculation logic",
        "sensitive_sections": [
            {"line_start": 5, "line_end": 15, "reason": "Progressive tax brackets"},
        ],
    }
    config = Config()
    lines = [f"line {i}" for i in range(30)]
    content = "\n".join(lines)
    findings = scan_content(content, "tax.py", config)
    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.SENSITIVE_ALGORITHM
    assert findings[0].line_number == 5
    assert findings[0].score == 0.85 * config.scoring.sensitive_algorithm


@patch("oss_sanitizer.scanners.algorithms._call_llm")
def test_sensitive_without_sections(mock_llm):
    mock_llm.return_value = {
        "is_sensitive": True,
        "confidence": 0.7,
        "explanation": "Government business logic",
        "sensitive_sections": [],
    }
    config = Config()
    content = "def process():\n    pass\n" * 10
    findings = scan_content(content, "processor.py", config)
    assert len(findings) == 1
    assert findings[0].line_number == 1
    assert "more lines" in findings[0].snippet


@patch("oss_sanitizer.scanners.algorithms._call_llm")
def test_llm_error_returns_empty(mock_llm):
    mock_llm.side_effect = Exception("API timeout")
    config = Config()
    content = "def process():\n    pass\n" * 10
    findings = scan_content(content, "processor.py", config)
    assert findings == []


@patch("oss_sanitizer.scanners.algorithms._call_llm")
def test_truncates_large_files(mock_llm):
    """Files > 8000 chars should be truncated before sending to LLM."""
    mock_llm.return_value = {"is_sensitive": False, "confidence": 0, "explanation": "", "sensitive_sections": []}
    config = Config()
    content = "x = 1\n" * 5000  # ~30000 chars
    scan_content(content, "big.py", config)
    # Verify the LLM was called with truncated content
    call_args = mock_llm.call_args[0][1]  # user_message
    assert len(call_args) < 10000


def test_commit_sha_passed_through():
    """When scanning history, commit_sha should be set on findings."""
    with patch("oss_sanitizer.scanners.algorithms._call_llm") as mock_llm:
        mock_llm.return_value = {
            "is_sensitive": True,
            "confidence": 0.9,
            "explanation": "test",
            "sensitive_sections": [{"line_start": 1, "line_end": 5, "reason": "test"}],
        }
        config = Config()
        content = "def calc():\n    pass\n" * 10
        findings = scan_content(content, "calc.py", config, commit_sha="abc123")
        assert findings[0].commit_sha == "abc123"
