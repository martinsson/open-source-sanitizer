"""Internal dependency detection from Maven pom.xml files."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from jinja2 import Environment, PackageLoader

from ..config import Config
from .pom.model import PomDependency, PomModel, parse as parse_pom_model

logger = logging.getLogger(__name__)

DEFAULT_INTERNAL_GROUP_PATTERNS = [
    r"ch\.ge\b",
    r"ch\.etat-ge\b",
    r"ch\.geneve\b",
    r"ch\.gva\b",
]


def _find_pom_files(repo_path: Path, config: Config) -> list[Path]:
    poms = []
    for pom in repo_path.rglob("pom.xml"):
        rel = str(pom.relative_to(repo_path))
        if not any(skip in rel for skip in config.patterns.skip_paths):
            poms.append(pom)
    return sorted(poms)


def parse_pom(pom_path: Path, repo_path: Path) -> list[PomDependency]:
    model = parse_pom_model(pom_path, repo_path)
    return [] if model is None else list(model.dependencies)


def _load_models(poms: list[Path], repo_path: Path) -> list[PomModel]:
    models = []
    for pom_path in poms:
        model = parse_pom_model(pom_path, repo_path)
        if model is not None:
            models.append(model)
    return models


def _collect_project_group_ids(models: list[PomModel]) -> set[str]:
    ids: set[str] = set()
    for model in models:
        if model.group_id:
            ids.add(model.group_id)
        if model.parent_group_id:
            ids.add(model.parent_group_id)
    return ids


def _filter_internal(
    models: list[PomModel],
    own_groups: set[str],
) -> list[PomDependency]:
    patterns = [re.compile(p) for p in DEFAULT_INTERNAL_GROUP_PATTERNS]
    seen: set[tuple[str, str]] = set()
    result: list[PomDependency] = []
    for dep in (d for model in models for d in model.dependencies):
        if not any(p.search(dep.group_id) for p in patterns):
            continue
        if dep.group_id in own_groups:
            continue
        key = (dep.group_id, dep.artifact_id)
        if key not in seen:
            seen.add(key)
            result.append(dep)
    return result


def find_internal_dependencies(
    repo_path: Path,
    config: Config,
    project_group_ids: set[str] | None = None,
) -> list[PomDependency]:
    """Find all internal dependencies across all pom.xml files."""
    poms = _find_pom_files(repo_path, config)
    if not poms:
        return []
    models = _load_models(poms, repo_path)
    own_groups = project_group_ids if project_group_ids is not None else _collect_project_group_ids(models)
    logger.info(f"Project groupIds: {own_groups}")
    return _filter_internal(models, own_groups)


_deps_env = Environment(
    loader=PackageLoader("oss_sanitizer", "templates"),
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_dependency_report(internal_deps: list[PomDependency], repo_path: str) -> str:
    """Render the internal dependencies as a markdown section."""
    _sort_key = lambda d: (d.group_id, d.artifact_id)
    shipping = sorted([d for d in internal_deps if d.is_shipping], key=_sort_key)
    non_shipping = sorted([d for d in internal_deps if not d.is_shipping], key=_sort_key)
    template = _deps_env.get_template("dependencies.md.j2")
    return template.render(deps=internal_deps, shipping=shipping, non_shipping=non_shipping).rstrip()
