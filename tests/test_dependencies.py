"""Tests for the Maven dependency scanner."""

from __future__ import annotations

from pathlib import Path

from oss_sanitizer.config import Config
from oss_sanitizer.scanners.dependencies import (
    parse_pom,
    find_internal_dependencies,
    render_dependency_report,
    _resolve_property,
)

from .conftest import FIXTURES


def test_parse_pom_extracts_all_deps(config: Config):
    pom_path = FIXTURES / "sample_pom.xml"
    deps = parse_pom(pom_path, FIXTURES)
    # 5 dependencies + 1 parent = 6
    assert len(deps) == 6
    group_ids = {d.group_id for d in deps}
    assert "ch.ge.common" in group_ids
    assert "ch.etat-ge.security" in group_ids
    assert "org.springframework.boot" in group_ids
    assert "ch.ge.testing" in group_ids
    assert "ch.ge.example" in group_ids  # own module + parent


def test_parse_pom_resolves_properties(config: Config):
    pom_path = FIXTURES / "sample_pom.xml"
    deps = parse_pom(pom_path, FIXTURES)
    commons = next(d for d in deps if d.artifact_id == "ge-commons")
    assert commons.version == "4.5.0"  # resolved from ${internal.lib.version}


def test_parse_pom_resolves_project_version(config: Config):
    pom_path = FIXTURES / "sample_pom.xml"
    deps = parse_pom(pom_path, FIXTURES)
    utils = next(d for d in deps if d.artifact_id == "example-utils")
    assert utils.version == "2.3.1"  # resolved from ${project.version}


def test_parse_pom_captures_scope(config: Config):
    pom_path = FIXTURES / "sample_pom.xml"
    deps = parse_pom(pom_path, FIXTURES)
    test_dep = next(d for d in deps if d.artifact_id == "test-helpers")
    assert test_dep.scope == "test"


def test_parse_pom_parent_scope(config: Config):
    pom_path = FIXTURES / "sample_pom.xml"
    deps = parse_pom(pom_path, FIXTURES)
    parent = next(d for d in deps if d.scope == "parent")
    assert parent.group_id == "ch.ge.example"
    assert parent.artifact_id == "example-parent"


def test_parse_pom_line_numbers(config: Config):
    pom_path = FIXTURES / "sample_pom.xml"
    deps = parse_pom(pom_path, FIXTURES)
    for dep in deps:
        assert dep.line_number >= 1


def _get_internal_deps(config: Config) -> list:
    """Helper: parse our fixture pom and filter internal deps."""
    pom_path = FIXTURES / "sample_pom.xml"
    all_deps = parse_pom(pom_path, FIXTURES)
    # Simulate what find_internal_dependencies does: filter by internal patterns,
    # exclude project's own groupIds
    import re
    from oss_sanitizer.scanners.dependencies import DEFAULT_INTERNAL_GROUP_PATTERNS
    patterns = [re.compile(p) for p in DEFAULT_INTERNAL_GROUP_PATTERNS]
    project_gids = {"ch.ge.example"}
    seen = set()
    internal = []
    for dep in all_deps:
        if not any(p.search(dep.group_id) for p in patterns):
            continue
        if dep.group_id in project_gids:
            continue
        key = (dep.group_id, dep.artifact_id)
        if key in seen:
            continue
        seen.add(key)
        internal.append(dep)
    return internal


def test_find_internal_dependencies_excludes_own_modules(config: Config):
    """Internal deps that are part of the project itself should be excluded."""
    internal = _get_internal_deps(config)
    internal_gids = {d.group_id for d in internal}
    assert "ch.ge.example" not in internal_gids
    assert "ch.ge.common" in internal_gids
    assert "ch.etat-ge.security" in internal_gids


def test_find_internal_dependencies_excludes_external(config: Config):
    """External deps (e.g., springframework) should not be flagged."""
    internal = _get_internal_deps(config)
    internal_gids = {d.group_id for d in internal}
    assert "org.springframework.boot" not in internal_gids


def test_find_internal_dependencies_deduplicates(config: Config):
    """Same groupId:artifactId should be deduped."""
    internal = _get_internal_deps(config)
    keys = [(d.group_id, d.artifact_id) for d in internal]
    assert len(keys) == len(set(keys))


def test_resolve_property():
    props = {"my.version": "1.2.3", "project.version": "2.0.0"}
    assert _resolve_property("${my.version}", props) == "1.2.3"
    assert _resolve_property("${project.version}", props) == "2.0.0"
    assert _resolve_property("literal", props) == "literal"
    assert _resolve_property(None, props) is None
    assert _resolve_property("${unknown}", props) == "${unknown}"


def test_render_dependency_report_shipping_vs_non_shipping(config: Config):
    """Report should separate shipping and non-shipping deps."""
    internal = _get_internal_deps(config)
    report = render_dependency_report(internal, str(FIXTURES))
    assert "Shipping dependencies" in report
    # ch.ge.testing has scope=test so should be non-shipping
    if any(d.scope == "test" for d in internal):
        assert "Non-shipping dependencies" in report


def test_render_dependency_report_empty():
    report = render_dependency_report([], "/tmp/repo")
    assert "No internal dependencies found" in report


def test_parse_malformed_pom():
    """Parsing a non-existent or malformed POM should return empty list."""
    deps = parse_pom(Path("/nonexistent/pom.xml"), Path("/nonexistent"))
    assert deps == []


def test_find_internal_dependencies_with_pom_file(config: Config, tmp_path: Path):
    """Integration test using find_internal_dependencies with a real pom.xml."""
    import shutil
    # Copy fixture as pom.xml in tmp dir
    shutil.copy(FIXTURES / "sample_pom.xml", tmp_path / "pom.xml")
    internal = find_internal_dependencies(tmp_path, config)
    internal_gids = {d.group_id for d in internal}
    # ch.ge.example is the project's own groupId, should be excluded
    assert "ch.ge.example" not in internal_gids
    # ch.ge.common and ch.etat-ge.security should be found
    assert "ch.ge.common" in internal_gids
    assert "ch.etat-ge.security" in internal_gids
    # External should not appear
    assert "org.springframework.boot" not in internal_gids


def test_find_internal_dependencies_skip_paths(config: Config, tmp_path: Path):
    """POMs in skip_paths should be ignored."""
    import shutil
    skip_dir = tmp_path / ".git" / "subdir"
    skip_dir.mkdir(parents=True)
    shutil.copy(FIXTURES / "sample_pom.xml", skip_dir / "pom.xml")
    internal = find_internal_dependencies(tmp_path, config)
    assert internal == []


def test_find_internal_dependencies_empty_repo(config: Config, tmp_path: Path):
    """Repo with no pom.xml should return empty list."""
    internal = find_internal_dependencies(tmp_path, config)
    assert internal == []


def test_get_line_number():
    from oss_sanitizer.scanners.dependencies import _get_line_number
    pom_text = (FIXTURES / "sample_pom.xml").read_text()
    # ge-commons should be findable
    line = _get_line_number(pom_text, "ch.ge.common", "ge-commons")
    assert line > 1
    # Non-existent artifact should return 1
    line = _get_line_number(pom_text, "no.such", "no-such-artifact")
    assert line == 1
