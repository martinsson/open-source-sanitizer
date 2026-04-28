"""Tests for the --fix replacement map generation and application."""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

from oss_sanitizer.config import Config
from oss_sanitizer.fixer import apply_fixes, build_replacement_map, write_replacement_map
from oss_sanitizer.models import Finding, FindingType
from oss_sanitizer.scanners.secrets import scan_for_secrets
from oss_sanitizer.scanners.urls import scan_for_internal_references

_SCORE = 5.0
_SCORE_SECRET = 10.0
_SCORE_ALGO = 3.0
_APP_PY = "app.py"
_API_CORP = "api.corp.net"
_BUILD_INTERNAL = "build.internal"
_SK = "sk-abc123"
_HOST_1 = "HOST_1"
_HOST_2 = "HOST_2"
_SECRET_1 = "SECRET_1"
_GIT = "git"
_FLAG_C = "-C"
_FLAG_M = "-m"


# ── match_value populated by scanners ────────────────────────────────


def test_url_finding_sets_match_value_to_hostname(config: Config):
    content = 'url = "https://api.etat-ge.ch/v2/citizens"'
    findings = scan_for_internal_references(content, _APP_PY, config)
    url_findings = [f for f in findings if f.finding_type == FindingType.INTERNAL_URL]
    assert url_findings[0].match_value == "api.etat-ge.ch"


def test_hostname_finding_sets_match_value(config: Config):
    content = 'host = "srv-db01.internal"'
    findings = scan_for_internal_references(content, _APP_PY, config)
    host_findings = [f for f in findings if f.finding_type == FindingType.INTERNAL_HOSTNAME]
    assert host_findings[0].match_value == "srv-db01.internal"


def test_secret_finding_sets_match_value(config: Config):
    content = "AWS_KEY = AKIAIOSFODNN7EXAMPLE"
    findings = scan_for_secrets(content, "config.py", config)
    assert findings[0].match_value == "AKIAIOSFODNN7EXAMPLE"


# ── build_replacement_map ─────────────────────────────────────────────


def _make_finding(ftype, match_value, file_path=_APP_PY):
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


def test_assigns_host_token_to_url_hostname():
    findings = [_make_finding(FindingType.INTERNAL_URL, "internal.company.com")]
    replacement_map = build_replacement_map(findings)
    assert replacement_map["internal.company.com"] == _HOST_1


def test_assigns_host_token_to_standalone_hostname():
    findings = [_make_finding(FindingType.INTERNAL_HOSTNAME, _BUILD_INTERNAL)]
    replacement_map = build_replacement_map(findings)
    assert replacement_map[_BUILD_INTERNAL] == _HOST_1


def test_url_and_hostname_findings_share_host_counter():
    findings = [
        _make_finding(FindingType.INTERNAL_URL, _API_CORP),
        _make_finding(FindingType.INTERNAL_HOSTNAME, _BUILD_INTERNAL),
    ]
    replacement_map = build_replacement_map(findings)
    tokens = set(replacement_map.values())
    assert tokens == {_HOST_1, _HOST_2}


def test_assigns_secret_token_to_secret():
    findings = [_make_finding(FindingType.SECRET, _SK)]
    replacement_map = build_replacement_map(findings)
    assert replacement_map[_SK] == _SECRET_1


def test_two_different_secrets_get_different_tokens():
    findings = [
        _make_finding(FindingType.SECRET, _SK),
        _make_finding(FindingType.SECRET, "ghp-xyz789"),
    ]
    replacement_map = build_replacement_map(findings)
    assert replacement_map[_SK] == _SECRET_1
    assert replacement_map["ghp-xyz789"] == "SECRET_2"


def test_same_match_value_across_findings_gets_one_token():
    findings = [
        _make_finding(FindingType.INTERNAL_URL, _API_CORP),
        _make_finding(FindingType.INTERNAL_URL, _API_CORP),
    ]
    replacement_map = build_replacement_map(findings)
    assert len(replacement_map) == 1
    assert replacement_map[_API_CORP] == _HOST_1


def test_findings_without_match_value_are_ignored():
    findings = [_make_finding(FindingType.SENSITIVE_ALGORITHM, None)]
    replacement_map = build_replacement_map(findings)
    assert replacement_map == {}


# ── write_replacement_map ─────────────────────────────────────────────


def test_write_replacement_map_creates_yaml_file(tmp_path):
    replacement_map = {_API_CORP: _HOST_1, _SK: _SECRET_1}
    out = tmp_path / "oss-sanitizer-replacements.yaml"
    write_replacement_map(replacement_map, out)
    assert out.exists()
    data = yaml.safe_load(out.read_text())
    assert data[_HOST_1] == _API_CORP
    assert data[_SECRET_1] == _SK


def test_write_replacement_map_empty_map(tmp_path):
    out = tmp_path / "oss-sanitizer-replacements.yaml"
    write_replacement_map({}, out)
    assert out.exists()
    data = yaml.safe_load(out.read_text())
    assert data == {} or data is None


# ── apply_fixes ───────────────────────────────────────────────────────


def _file_finding(file_path, ftype, match_value, score=_SCORE):
    return Finding(
        finding_type=ftype,
        description="test",
        file_path=str(file_path),
        line_number=1,
        score=score,
        snippet="",
        explanation="",
        match_value=match_value,
    )


def test_apply_fixes_replaces_hostname_in_file(tmp_path):
    src = tmp_path / _APP_PY
    src.write_text('url = "https://api.corp.net/v1/data"\n')
    findings = [_file_finding(src, FindingType.INTERNAL_URL, _API_CORP)]
    apply_fixes(findings, {_API_CORP: _HOST_1})
    assert src.read_text() == 'url = "https://HOST_1/v1/data"\n'


def test_apply_fixes_replaces_secret_in_file(tmp_path):
    src = tmp_path / "config.py"
    src.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = [_file_finding(src, FindingType.SECRET, "AKIAIOSFODNN7EXAMPLE", score=_SCORE_SECRET)]
    apply_fixes(findings, {"AKIAIOSFODNN7EXAMPLE": _SECRET_1})
    assert src.read_text() == 'AWS_KEY = "SECRET_1"\n'


def test_apply_fixes_multiple_replacements_in_same_file(tmp_path):
    src = tmp_path / "config.py"
    src.write_text('url = "https://api.corp.net/v1"\nhost = "build.internal"\n')
    findings = [
        _file_finding(src, FindingType.INTERNAL_URL, _API_CORP),
        _file_finding(src, FindingType.INTERNAL_HOSTNAME, _BUILD_INTERNAL),
    ]
    apply_fixes(findings, {_API_CORP: _HOST_1, _BUILD_INTERNAL: _HOST_2})
    text = src.read_text()
    assert _HOST_1 in text and _HOST_2 in text
    assert _API_CORP not in text and _BUILD_INTERNAL not in text


def test_apply_fixes_replaces_all_occurrences_in_file(tmp_path):
    src = tmp_path / _APP_PY
    src.write_text('A = "https://api.corp.net/a"\nB = "https://api.corp.net/b"\n')
    findings = [_file_finding(src, FindingType.INTERNAL_URL, _API_CORP)]
    apply_fixes(findings, {_API_CORP: _HOST_1})
    text = src.read_text()
    assert text.count(_HOST_1) == 2
    assert _API_CORP not in text


def test_apply_fixes_skips_findings_without_match_value(tmp_path):
    src = tmp_path / "algo.py"
    original = "def encrypt(data): pass\n"
    src.write_text(original)
    findings = [_file_finding(src, FindingType.SENSITIVE_ALGORITHM, None, score=_SCORE_ALGO)]
    apply_fixes(findings, {})
    assert src.read_text() == original


# ── CLI --fix integration ─────────────────────────────────────────────


def _git(path, *args):
    subprocess.run([_GIT, _FLAG_C, str(path), *args], check=True, capture_output=True)


def _init_git_repo(path: Path) -> None:
    subprocess.run([_GIT, "init", str(path)], check=True, capture_output=True)
    _git(path, "config", "user.email", "test@test.com")
    _git(path, "config", "user.name", "Test")
    (path / ".gitkeep").write_text("")
    _git(path, "add", ".gitkeep")
    _git(path, "commit", _FLAG_M, "init")


def _run_cli(repo_path, *extra_args):
    return subprocess.run(
        ["python", _FLAG_M, "oss_sanitizer.cli", str(repo_path), *extra_args],
        capture_output=True,
        text=True,
    )


def test_fix_flag_modifies_file_in_repo(tmp_path):
    _init_git_repo(tmp_path)
    src = tmp_path / _APP_PY
    src.write_text('url = "https://api.etat-ge.ch/v2/citizens"\n')
    result = _run_cli(tmp_path, "--fix")
    assert result.returncode in (0, 2)
    assert "api.etat-ge.ch" not in src.read_text()
    assert "HOST_" in src.read_text()


def test_fix_flag_writes_replacement_map(tmp_path):
    _init_git_repo(tmp_path)
    src = tmp_path / _APP_PY
    src.write_text('url = "https://api.etat-ge.ch/v2/citizens"\n')
    _run_cli(tmp_path, "--fix")
    map_file = tmp_path / "oss-sanitizer-replacements.yaml"
    assert map_file.exists()
    data = yaml.safe_load(map_file.read_text())
    assert "api.etat-ge.ch" in data.values()


def test_fix_flag_absent_leaves_files_unchanged(tmp_path):
    _init_git_repo(tmp_path)
    src = tmp_path / _APP_PY
    original = 'url = "https://api.etat-ge.ch/v2/citizens"\n'
    src.write_text(original)
    _run_cli(tmp_path)
    assert src.read_text() == original
