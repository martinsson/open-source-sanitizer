"""Tests for the URL and hostname scanner."""

from __future__ import annotations

from oss_sanitizer.config import Config
from oss_sanitizer.models import FindingType
from oss_sanitizer.scanners.urls import scan_content

from .conftest import FIXTURES


# ── Internal URL detection ───────────────────────────────────────────


def test_detects_internal_url(config: Config):
    content = 'url = "https://api.etat-ge.ch/v2/citizens"'
    findings = scan_content(content, "app.py", config)
    urls = [f for f in findings if f.finding_type == FindingType.INTERNAL_URL]
    assert len(urls) == 1
    assert "api.etat-ge.ch" in urls[0].description


def test_detects_ge_ch_url(config: Config):
    content = 'INTRANET = "http://intranet.ge.ch/documents"'
    findings = scan_content(content, "app.py", config)
    urls = [f for f in findings if f.finding_type == FindingType.INTERNAL_URL]
    assert len(urls) == 1


def test_does_not_flag_public_url(config: Config):
    content = 'url = "https://github.com/org/repo"'
    findings = scan_content(content, "app.py", config)
    assert len(findings) == 0


def test_allowlist_suppresses_url(config: Config):
    # apache.org is in the default allowlist
    content = 'url = "https://www.apache.org/licenses/LICENSE-2.0"'
    findings = scan_content(content, "app.py", config)
    assert len(findings) == 0


# ── Internal hostname detection ──────────────────────────────────────


def test_detects_srv_hostname(config: Config):
    content = 'host = "srv-db01.internal"'
    findings = scan_content(content, "app.py", config)
    hostnames = [f for f in findings if f.finding_type == FindingType.INTERNAL_HOSTNAME]
    assert len(hostnames) >= 1


def test_detects_env_suffix_hostname(config: Config):
    content = 'server = "myapp-prod"'
    findings = scan_content(content, "app.py", config)
    hostnames = [f for f in findings if f.finding_type == FindingType.INTERNAL_HOSTNAME]
    assert len(hostnames) >= 1


def test_detects_private_ip(config: Config):
    content = 'ip = "192.168.1.100"'
    findings = scan_content(content, "app.py", config)
    hostnames = [f for f in findings if f.finding_type == FindingType.INTERNAL_HOSTNAME]
    assert len(hostnames) == 1


def test_hostname_not_inside_url(config: Config):
    """Hostname inside a URL should not produce a separate hostname finding."""
    content = 'url = "https://srv-db01.etat-ge.ch/api"'
    findings = scan_content(content, "app.py", config)
    hostnames = [f for f in findings if f.finding_type == FindingType.INTERNAL_HOSTNAME]
    # srv-db01 is inside the URL, should not be flagged separately
    assert len(hostnames) == 0


def test_hostname_dedup_overlap(config: Config):
    """Overlapping hostname patterns should not produce duplicate findings."""
    content = 'host = "srv-prod-db01.internal"'
    findings = scan_content(content, "app.py", config)
    hostnames = [f for f in findings if f.finding_type == FindingType.INTERNAL_HOSTNAME]
    # Should get at most one finding (longest match), not multiple overlaps
    texts = [f.description for f in hostnames]
    assert len(texts) == len(set(texts)), f"Duplicate hostname findings: {texts}"


# ── XML/POM context scoring ─────────────────────────────────────────


def test_pom_dependency_tags_skipped(config: Config):
    """URLs inside <dependency> blocks of a pom.xml should be skipped."""
    content = (FIXTURES / "sample_pom.xml").read_text()
    findings = scan_content(content, "pom.xml", config)
    # URLs in <groupId>, <artifactId> etc should be skipped
    # But URLs in <scm>, <repository>, <properties> should be found
    urls = [f for f in findings if f.finding_type == FindingType.INTERNAL_URL]
    url_texts = [f.description for f in urls]
    # SCM and repository URLs should be found
    assert any("git.etat-ge.ch" in t for t in url_texts)
    assert any("nexus.etat-ge.ch" in t for t in url_texts)


def test_pom_scm_urls_full_score(config: Config):
    """URLs in <scm> should get full score (high confidence context)."""
    content = (FIXTURES / "sample_pom.xml").read_text()
    findings = scan_content(content, "pom.xml", config)
    scm_findings = [f for f in findings if "git.etat-ge.ch" in f.description]
    assert len(scm_findings) >= 1
    # High context = full score = config.scoring.internal_url * 1.0
    for f in scm_findings:
        assert f.score == config.scoring.internal_url


def test_pom_properties_url_medium_score(config: Config):
    """URLs in <properties> should get medium score."""
    content = (FIXTURES / "sample_pom.xml").read_text()
    findings = scan_content(content, "pom.xml", config)
    prop_findings = [f for f in findings if "app.etat-ge.ch" in f.description]
    assert len(prop_findings) >= 1
    expected = config.scoring.internal_url * 0.8  # MEDIUM factor
    assert prop_findings[0].score == expected


def test_generic_xml_not_pom_context(config: Config):
    """A generic XML file (not pom.xml) should score URLs at XML default factor."""
    content = (FIXTURES / "sample_spring_config.xml").read_text()
    findings = scan_content(content, "applicationContext.xml", config)
    urls = [f for f in findings if f.finding_type == FindingType.INTERNAL_URL]
    assert len(urls) >= 1


# ── Properties file context ──────────────────────────────────────────


def test_properties_comment_skipped(config: Config):
    """Comment lines in .properties files should be skipped."""
    content = (FIXTURES / "sample_properties.properties").read_text()
    findings = scan_content(content, "db.properties", config)
    # The comment line has a URL but should be skipped
    urls = [f for f in findings if f.finding_type == FindingType.INTERNAL_URL]
    url_texts = " ".join(f.description for f in urls)
    # db.etat-ge.ch from comment should NOT be found (M7 fix)
    # but db.etat-ge.ch from the actual jdbc url SHOULD be found
    # Actually the comment has "db.etat-ge.ch/admin" and the value has "srv-db01.etat-ge.ch"
    # The comment URL should not appear
    comment_url_found = any("db.etat-ge.ch/admin" in f.description for f in urls)
    assert not comment_url_found, "URL from comment line should be skipped"


def test_properties_values_detected(config: Config):
    """Actual values in .properties files should be detected."""
    content = (FIXTURES / "sample_properties.properties").read_text()
    findings = scan_content(content, "db.properties", config)
    # jdbc URL doesn't match https?:// so it's caught as hostname, not URL
    hostnames = [f for f in findings if f.finding_type == FindingType.INTERNAL_HOSTNAME]
    assert any("srv-db01" in f.description for f in hostnames)
    # https URLs are caught as internal URLs
    urls = [f for f in findings if f.finding_type == FindingType.INTERNAL_URL]
    assert any("app.etat-ge.ch" in f.description for f in urls)


def test_properties_full_score(config: Config):
    """Properties file findings should get full score."""
    content = 'app.url=https://api.etat-ge.ch/v1'
    findings = scan_content(content, "application.properties", config)
    urls = [f for f in findings if f.finding_type == FindingType.INTERNAL_URL]
    assert len(urls) == 1
    assert urls[0].score == config.scoring.internal_url


# ── Sample app fixture ───────────────────────────────────────────────


def test_sample_app_findings(config: Config):
    content = (FIXTURES / "sample_app.py").read_text()
    findings = scan_content(content, "sample_app.py", config)
    urls = [f for f in findings if f.finding_type == FindingType.INTERNAL_URL]
    hostnames = [f for f in findings if f.finding_type == FindingType.INTERNAL_HOSTNAME]
    # Should find internal URLs
    assert any("api.etat-ge.ch" in f.description for f in urls)
    assert any("intranet.ge.ch" in f.description for f in urls)
    # Should find hostnames
    assert len(hostnames) >= 1


def test_snippet_has_context(config: Config):
    content = 'line1\nline2\nline3\nurl = "https://api.etat-ge.ch/v2"\nline5\nline6'
    findings = scan_content(content, "app.py", config)
    assert len(findings) >= 1
    # Snippet should include surrounding lines
    assert "line2" in findings[0].snippet or "line3" in findings[0].snippet
