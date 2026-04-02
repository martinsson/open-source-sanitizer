"""Tests for the Markdown report generator."""

from __future__ import annotations

from oss_sanitizer.models import Finding, FindingType, ScanReport
from oss_sanitizer.scanners.pom_model import PomDependency
from oss_sanitizer.report import render_markdown


def _make_report(findings=None, deps=None) -> ScanReport:
    report = ScanReport(repo_path="/tmp/test-repo", scan_history=False)
    if findings:
        report.findings = findings
    if deps:
        report.internal_dependencies = deps
    return report


def test_render_empty_report():
    report = _make_report()
    md = render_markdown(report)
    assert "# OSS Sanitizer — Compliance Report" in md
    assert "No findings" in md
    assert "Total findings:** 0" in md


def test_render_report_has_metadata():
    report = _make_report()
    md = render_markdown(report)
    assert "**Repository:** `/tmp/test-repo`" in md
    assert "**Date:**" in md
    assert "UTC" in md
    assert "**History scanned:** No" in md


def test_render_report_timestamp_has_seconds():
    """M6 fix: timestamp should include seconds."""
    report = _make_report()
    md = render_markdown(report)
    # Should match pattern like 2026-04-01 12:34:56 UTC
    import re
    assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC", md)


def test_render_report_with_findings():
    findings = [
        Finding(FindingType.SECRET, "API key found", "app.py", 10, 10.0,
                "  10 | API_KEY = sk-...", "Remove secrets per Charte §2"),
        Finding(FindingType.INTERNAL_URL, "Internal URL: https://api.etat-ge.ch",
                "config.py", 5, 7.0, "   5 | url = https://api...",
                "Remove internal URLs per Charte §2"),
    ]
    report = _make_report(findings=findings)
    md = render_markdown(report)

    # Summary table
    assert "| Secrets & Credentials | 1 |" in md
    assert "| Internal URLs | 1 |" in md

    # Detailed sections
    assert "## Secrets & Credentials" in md
    assert "## Internal URLs" in md
    assert "API key found" in md
    assert "**File:** `app.py`" in md
    assert "**Line:** 10" in md
    assert "**Score:** 10.0" in md
    assert "**Why:** Remove secrets per Charte §2" in md

    # Bottom summary (repeated)
    assert "## Summary (repeat)" in md


def test_render_report_with_commit_sha():
    findings = [
        Finding(FindingType.SECRET, "test", "f.py", 1, 10.0, "", "",
                commit_sha="abc123def456"),
    ]
    report = _make_report(findings=findings)
    md = render_markdown(report)
    assert "abc123def456" in md


def test_render_report_with_dependencies():
    deps = [
        PomDependency("ch.ge.common", "ge-commons", "1.0", None, "pom.xml", 10),
        PomDependency("ch.ge.test", "test-utils", "2.0", "test", "pom.xml", 20),
    ]
    # Need at least one finding for the report to render deps/footer sections
    findings = [
        Finding(FindingType.SECRET, "test", "f.py", 1, 10.0, "", ""),
    ]
    report = _make_report(findings=findings, deps=deps)
    md = render_markdown(report)
    assert "Internal Dependencies" in md
    assert "ge-commons" in md
    assert "test-utils" in md


def test_render_report_footer():
    findings = [
        Finding(FindingType.SECRET, "test", "f.py", 1, 10.0, "", ""),
    ]
    report = _make_report(findings=findings)
    md = render_markdown(report)
    assert "oss-sanitizer" in md
    assert "Charte Open Source" in md


def test_render_report_history_flag():
    report = _make_report()
    report.scan_history = True
    md = render_markdown(report)
    assert "**History scanned:** Yes" in md
