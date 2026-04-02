"""Tests for data models."""

from __future__ import annotations

from oss_sanitizer.models import Finding, FindingType, ScanReport


def test_finding_type_values():
    assert FindingType.SECRET.value == "secret"
    assert FindingType.INTERNAL_URL.value == "internal_url"
    assert FindingType.INTERNAL_HOSTNAME.value == "internal_hostname"
    assert FindingType.SENSITIVE_ALGORITHM.value == "sensitive_algorithm"


def test_scan_report_total_score():
    report = ScanReport(repo_path="/tmp", scan_history=False)
    report.findings = [
        Finding(FindingType.SECRET, "test", "f.py", 1, 5.0, "", ""),
        Finding(FindingType.INTERNAL_URL, "test", "f.py", 2, 3.0, "", ""),
    ]
    assert report.total_score == 8.0


def test_scan_report_total_score_empty():
    report = ScanReport(repo_path="/tmp", scan_history=False)
    assert report.total_score == 0.0


def test_findings_by_type_groups_correctly():
    report = ScanReport(repo_path="/tmp", scan_history=False)
    report.findings = [
        Finding(FindingType.SECRET, "s1", "f.py", 1, 5.0, "", ""),
        Finding(FindingType.SECRET, "s2", "f.py", 2, 10.0, "", ""),
        Finding(FindingType.INTERNAL_URL, "u1", "f.py", 3, 3.0, "", ""),
    ]
    grouped = report.findings_by_type()
    assert len(grouped[FindingType.SECRET]) == 2
    assert len(grouped[FindingType.INTERNAL_URL]) == 1
    assert FindingType.INTERNAL_HOSTNAME not in grouped


def test_findings_by_type_sorted_by_score_desc():
    report = ScanReport(repo_path="/tmp", scan_history=False)
    report.findings = [
        Finding(FindingType.SECRET, "low", "f.py", 1, 2.0, "", ""),
        Finding(FindingType.SECRET, "high", "f.py", 2, 9.0, "", ""),
        Finding(FindingType.SECRET, "mid", "f.py", 3, 5.0, "", ""),
    ]
    grouped = report.findings_by_type()
    scores = [f.score for f in grouped[FindingType.SECRET]]
    assert scores == [9.0, 5.0, 2.0]
