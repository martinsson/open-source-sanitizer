"""Tests for the secrets scanner."""

from __future__ import annotations

from oss_sanitizer.config import Config
from oss_sanitizer.models import FindingType
from oss_sanitizer.scanners.secrets import scan_for_secrets, is_false_positive_path

from .conftest import FIXTURES


def test_detects_api_key(config: Config):
    content = 'API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678"'
    findings = scan_for_secrets(content, "app.py", config)
    assert len(findings) >= 1
    assert any(f.finding_type == FindingType.SECRET for f in findings)


def test_detects_aws_key(config: Config):
    content = "AWS_KEY = AKIAIOSFODNN7EXAMPLE"
    findings = scan_for_secrets(content, "config.py", config)
    assert len(findings) == 1
    assert "AWS" in findings[0].description


def test_detects_private_key(config: Config):
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...\n-----END RSA PRIVATE KEY-----"
    findings = scan_for_secrets(content, "key.pem", config)
    assert len(findings) >= 1
    assert any("Private Key" in f.description or "private" in f.description.lower() for f in findings)


def test_detects_password(config: Config):
    content = 'password = "SuperSecret123!"'
    findings = scan_for_secrets(content, "config.py", config)
    assert len(findings) >= 1
    # detect-secrets KeywordDetector reports "Secret Keyword"
    assert any("Secret Keyword" in f.description or "password" in f.description.lower() for f in findings)


def test_detects_connection_string_via_basic_auth(config: Config):
    """detect-secrets catches basic auth in URLs (user:pass@host), not jdbc://."""
    content = "db.url=postgresql://myuser:mysecretpassword@srv-db01:5432/mydb"
    findings = scan_for_secrets(content, "config.properties", config)
    assert len(findings) >= 1


def test_detects_github_token(config: Config):
    content = 'token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"'
    findings = scan_for_secrets(content, "ci.yml", config)
    assert len(findings) >= 1


def test_no_false_positive_on_empty(config: Config):
    findings = scan_for_secrets("", "app.py", config)
    assert findings == []


def test_no_false_positive_on_normal_code(config: Config):
    content = """
def hello():
    print("Hello, world!")
    return 42
"""
    findings = scan_for_secrets(content, "app.py", config)
    assert findings == []


def test_one_finding_per_line(config: Config):
    # A line matching multiple patterns should only produce one finding
    content = 'api_key = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"'
    findings = scan_for_secrets(content, "app.py", config)
    assert len(findings) == 1


def test_secret_masked_in_snippet(config: Config):
    content = 'API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678"'
    findings = scan_for_secrets(content, "app.py", config)
    assert len(findings) >= 1
    # The full secret should NOT appear in the snippet
    assert "sk-proj-abc123def456ghi789jkl012mno345pqr678" not in findings[0].snippet


def test_false_positive_path_lockfile():
    assert is_false_positive_path("package-lock.json")
    assert is_false_positive_path("node_modules/package-lock.json")


def test_false_positive_path_normal():
    assert not is_false_positive_path("src/app.py")
    assert not is_false_positive_path("config/settings.yaml")


def test_score_uses_config_weight():
    config = Config()
    config.scoring.secret = 5.0  # Half the default
    content = "-----BEGIN RSA PRIVATE KEY-----"
    findings = scan_for_secrets(content, "key.pem", config)
    assert len(findings) == 1
    # base_score=10.0 * config.scoring.secret/10.0 = 10.0 * 0.5 = 5.0
    assert findings[0].score == 5.0


def test_sample_app_fixture(config: Config):
    content = (FIXTURES / "sample_app.py").read_text()
    findings = scan_for_secrets(content, "sample_app.py", config)
    # detect-secrets should find multiple secrets (API key, AWS key, password)
    assert len(findings) >= 2
    descriptions = [f.description for f in findings]
    # detect-secrets types: "Base64 High Entropy String", "Secret Keyword", "AWS Access Key", etc.
    assert any("AWS" in d or "Keyword" in d or "Entropy" in d or "Key" in d for d in descriptions)
