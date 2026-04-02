"""Tests for the secrets scanner."""

from __future__ import annotations

from oss_sanitizer.config import Config
from oss_sanitizer.models import FindingType
from oss_sanitizer.scanners.secrets import scan_content, is_false_positive_path

from .conftest import FIXTURES


def test_detects_api_key(config: Config):
    content = 'API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678"'
    findings = scan_content(content, "app.py", config)
    assert len(findings) >= 1
    assert any(f.finding_type == FindingType.SECRET for f in findings)


def test_detects_aws_key(config: Config):
    content = "AWS_KEY = AKIAIOSFODNN7EXAMPLE"
    findings = scan_content(content, "config.py", config)
    assert len(findings) == 1
    assert "AWS" in findings[0].description


def test_detects_private_key(config: Config):
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...\n-----END RSA PRIVATE KEY-----"
    findings = scan_content(content, "key.pem", config)
    assert len(findings) == 1
    assert "Private key" in findings[0].description


def test_detects_password(config: Config):
    content = 'password = "SuperSecret123!"'
    findings = scan_content(content, "config.py", config)
    assert len(findings) >= 1
    assert any("password" in f.description.lower() for f in findings)


def test_detects_connection_string(config: Config):
    content = "jdbc:postgresql://srv-db01.etat-ge.ch:5432/mydb"
    findings = scan_content(content, "config.py", config)
    assert len(findings) == 1
    assert "connection string" in findings[0].description.lower()


def test_detects_github_token(config: Config):
    content = 'token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"'
    findings = scan_content(content, "ci.yml", config)
    assert len(findings) >= 1


def test_no_false_positive_on_empty(config: Config):
    findings = scan_content("", "app.py", config)
    assert findings == []


def test_no_false_positive_on_normal_code(config: Config):
    content = """
def hello():
    print("Hello, world!")
    return 42
"""
    findings = scan_content(content, "app.py", config)
    assert findings == []


def test_one_finding_per_line(config: Config):
    # A line matching multiple patterns should only produce one finding
    content = 'api_key = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"'
    findings = scan_content(content, "app.py", config)
    assert len(findings) == 1


def test_secret_masked_in_snippet(config: Config):
    content = 'API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678"'
    findings = scan_content(content, "app.py", config)
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
    findings = scan_content(content, "key.pem", config)
    assert len(findings) == 1
    # base_score=10.0 * config.scoring.secret/10.0 = 10.0 * 0.5 = 5.0
    assert findings[0].score == 5.0


def test_sample_app_fixture(config: Config):
    content = (FIXTURES / "sample_app.py").read_text()
    findings = scan_content(content, "sample_app.py", config)
    # Should detect API key, AWS key, and password
    assert len(findings) >= 3
    descriptions = [f.description for f in findings]
    assert any("API key" in d or "Generic secret" in d for d in descriptions)
    assert any("AWS" in d for d in descriptions)
    assert any("password" in d.lower() for d in descriptions)
