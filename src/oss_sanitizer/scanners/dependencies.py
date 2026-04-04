"""Internal dependency detection from Maven pom.xml files."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from jinja2 import Environment, PackageLoader

from ..config import Config
from .pom.model import PomDependency, PomModel, parse as parse_pom_model

logger = logging.getLogger(__name__)

# Default patterns that indicate an internal (government) dependency
DEFAULT_INTERNAL_GROUP_PATTERNS = [
    r"ch\.ge\b",
    r"ch\.etat-ge\b",
    r"ch\.geneve\b",
    r"ch\.gva\b",
]


def _find_pom_files(repo_path: Path, config: Config) -> list[Path]:
    """Find all pom.xml files in the repository."""
    poms = []
    for pom in repo_path.rglob("pom.xml"):
        rel = str(pom.relative_to(repo_path))
        if any(skip in rel for skip in config.patterns.skip_paths):
            continue
        poms.append(pom)
    return sorted(poms)


def parse_pom(pom_path: Path, repo_path: Path) -> list[PomDependency]:
    """Parse a pom.xml and extract all dependencies."""
    model = parse_pom_model(pom_path, repo_path)
    if model is None:
        return []
    return list(model.dependencies)


def find_internal_dependencies(
    repo_path: Path,
    config: Config,
    project_group_ids: set[str] | None = None,
) -> list[PomDependency]:
    """Find all internal dependencies across all pom.xml files.

    A dependency is considered internal if:
    1. Its groupId matches an internal pattern (e.g., ch.ge.*), AND
    2. It is NOT a module of the project being analyzed.
    """
    poms = _find_pom_files(repo_path, config)
    if not poms:
        return []

    # Parse all POMs once
    models: list[PomModel] = []
    for pom_path in poms:
        model = parse_pom_model(pom_path, repo_path)
        if model is not None:
            models.append(model)

    # First pass: collect this project's own groupIds
    if project_group_ids is None:
        project_group_ids = set()
        for model in models:
            if model.group_id:
                project_group_ids.add(model.group_id)
            if model.parent_group_id:
                project_group_ids.add(model.parent_group_id)

    logger.info(f"Project groupIds: {project_group_ids}")

    internal_patterns = [re.compile(p) for p in DEFAULT_INTERNAL_GROUP_PATTERNS]

    # Collect all dependencies from all POMs, then filter to internal
    all_deps = [d for model in models for d in model.dependencies]

    internal: list[PomDependency] = []
    seen: set[tuple[str, str]] = set()
    for dep in all_deps:
        if not any(p.search(dep.group_id) for p in internal_patterns):
            continue
        if dep.group_id in project_group_ids:
            continue
        key = (dep.group_id, dep.artifact_id)
        if key in seen:
            continue
        seen.add(key)
        internal.append(dep)

    return internal


_deps_env = Environment(
    loader=PackageLoader("oss_sanitizer", "templates"),
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_dependency_report(
    internal_deps: list[PomDependency],
    repo_path: str,
) -> str:
    """Render the internal dependencies as a markdown section."""
    _sort_key = lambda d: (d.group_id, d.artifact_id)
    shipping = sorted([d for d in internal_deps if d.is_shipping], key=_sort_key)
    non_shipping = sorted([d for d in internal_deps if not d.is_shipping], key=_sort_key)

    template = _deps_env.get_template("dependencies.md.j2")
    return template.render(
        deps=internal_deps,
        shipping=shipping,
        non_shipping=non_shipping,
    ).rstrip()
