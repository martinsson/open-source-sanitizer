"""Tests for the Scrubber domain object."""

from __future__ import annotations

from oss_sanitizer.models import Finding, FindingType
from oss_sanitizer.scrubber import Scrubber

_SCORE = 5.0
_HOST = "HOST"
_SECRET = "SECRET"
_API_CORP = "api.corp.net"
_BUILD_INTERNAL = "build.internal"
_HOST_1 = "HOST_1"
_HOST_2 = "HOST_2"
_SECRET_1 = "SECRET_1"
_HOST_TYPES = frozenset({FindingType.INTERNAL_URL, FindingType.INTERNAL_HOSTNAME})
_SECRET_TYPES = frozenset({FindingType.SECRET})


def _make_finding(ftype, match_value, file_path="app.py"):
    return Finding(
        finding_type=ftype,
        description="test",
        file_path=file_path,
        line_number=1,
        score=_SCORE,
        snippet="",
        explanation="",
        match_value=match_value,
    )


def _hostname_scrubber():
    return Scrubber(_HOST, _HOST_TYPES)


def _secret_scrubber():
    return Scrubber(_SECRET, _SECRET_TYPES)


# ── token assignment ──────────────────────────────────────────────────


def test_assigns_host_token_to_url_hostname():
    s = _hostname_scrubber()
    s.register([_make_finding(FindingType.INTERNAL_URL, _API_CORP)])
    assert s.replacements[_API_CORP] == _HOST_1


def test_assigns_host_token_to_standalone_hostname():
    s = _hostname_scrubber()
    s.register([_make_finding(FindingType.INTERNAL_HOSTNAME, _BUILD_INTERNAL)])
    assert s.replacements[_BUILD_INTERNAL] == _HOST_1


def test_assigns_secret_token():
    s = _secret_scrubber()
    s.register([_make_finding(FindingType.SECRET, "sk-abc")])
    assert s.replacements["sk-abc"] == _SECRET_1


def test_different_values_get_different_tokens():
    s = _hostname_scrubber()
    s.register([
        _make_finding(FindingType.INTERNAL_URL, _API_CORP),
        _make_finding(FindingType.INTERNAL_HOSTNAME, _BUILD_INTERNAL),
    ])
    assert s.replacements[_API_CORP] == _HOST_1
    assert s.replacements[_BUILD_INTERNAL] == _HOST_2


def test_ignores_unrelated_finding_types():
    s = _hostname_scrubber()
    s.register([_make_finding(FindingType.SECRET, "sk-abc")])
    assert s.replacements == {}


def test_findings_without_match_value_are_skipped():
    s = _hostname_scrubber()
    s.register([_make_finding(FindingType.INTERNAL_URL, None)])
    assert s.replacements == {}


# ── scrubbing guarantees ──────────────────────────────────────────────


def test_same_hostname_in_different_files_gets_same_token():
    """Core scrubbing guarantee: one hostname → one token across all files."""
    s = _hostname_scrubber()
    s.register([
        _make_finding(FindingType.INTERNAL_URL, _API_CORP, file_path="a.py"),
        _make_finding(FindingType.INTERNAL_URL, _API_CORP, file_path="b.py"),
    ])
    scrubbed_a = s.scrub(f'url = "https://{_API_CORP}/endpoint"')
    scrubbed_b = s.scrub(f'url = "https://{_API_CORP}/other"')
    assert _HOST_1 in scrubbed_a and _API_CORP not in scrubbed_a
    assert _HOST_1 in scrubbed_b and _API_CORP not in scrubbed_b


def test_path_preserved_same_hostname_different_paths():
    """Only the hostname is replaced; scheme and path are kept intact."""
    s = _hostname_scrubber()
    s.register([_make_finding(FindingType.INTERNAL_URL, _API_CORP)])
    assert s.scrub(f"https://{_API_CORP}/a") == f"https://{_HOST_1}/a"
    assert s.scrub(f"https://{_API_CORP}/b") == f"https://{_HOST_1}/b"
