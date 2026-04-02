"""Internal dependency detection from Maven pom.xml files."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from ..config import Config
from .pom_model import PomModel, parse as parse_pom_model

logger = logging.getLogger(__name__)

# Default patterns that indicate an internal (government) dependency
DEFAULT_INTERNAL_GROUP_PATTERNS = [
    r"ch\.ge\b",
    r"ch\.etat-ge\b",
    r"ch\.geneve\b",
    r"ch\.gva\b",
]


@dataclass
class Dependency:
    """A Maven dependency."""

    group_id: str
    artifact_id: str
    version: str | None
    scope: str | None
    pom_path: str
    line_number: int


def _find_pom_files(repo_path: Path, config: Config) -> list[Path]:
    """Find all pom.xml files in the repository."""
    poms = []
    for pom in repo_path.rglob("pom.xml"):
        rel = str(pom.relative_to(repo_path))
        if any(skip in rel for skip in config.patterns.skip_paths):
            continue
        poms.append(pom)
    return sorted(poms)


def parse_pom(pom_path: Path, repo_path: Path) -> list[Dependency]:
    """Parse a pom.xml and extract all dependencies."""
    model = parse_pom_model(pom_path, repo_path)
    if model is None:
        return []

    deps: list[Dependency] = []
    for d in model.dependencies:
        deps.append(Dependency(
            group_id=d.group_id,
            artifact_id=d.artifact_id,
            version=d.version,
            scope=d.scope,
            pom_path=model.path,
            line_number=d.line_number,
        ))
    return deps


def find_internal_dependencies(
    repo_path: Path,
    config: Config,
    project_group_ids: set[str] | None = None,
) -> list[Dependency]:
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

    # Second pass: collect internal dependencies
    all_deps: list[Dependency] = []
    for model in models:
        for d in model.dependencies:
            all_deps.append(Dependency(
                group_id=d.group_id,
                artifact_id=d.artifact_id,
                version=d.version,
                scope=d.scope,
                pom_path=model.path,
                line_number=d.line_number,
            ))

    internal: list[Dependency] = []
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


def render_dependency_report(
    internal_deps: list[Dependency],
    repo_path: str,
) -> str:
    """Render the internal dependencies as a markdown section."""
    lines: list[str] = []

    lines.append("## Internal Dependencies")
    lines.append("")
    lines.append("*Dependencies whose groupId matches internal Geneva patterns (ch.ge.*, ch.etat-ge.*, etc.) "
                 "and are not modules of the project being analyzed.*")
    lines.append("")

    if not internal_deps:
        lines.append("> No internal dependencies found.")
        return "\n".join(lines)

    lines.append(f"**{len(internal_deps)}** internal dependencies found:")
    lines.append("")

    NON_SHIPPING_SCOPES = {"test", "provided", "system"}
    shipping = [d for d in internal_deps if (d.scope or "compile") not in NON_SHIPPING_SCOPES]
    non_shipping = [d for d in internal_deps if (d.scope or "compile") in NON_SHIPPING_SCOPES]

    if shipping:
        lines.append(f"### Shipping dependencies ({len(shipping)})")
        lines.append("")
        lines.append("These must be made available publicly or mocked/documented per Charte §5 (Isolation).")
        lines.append("")
        lines.append("| groupId | artifactId | Version | Scope | Found in |")
        lines.append("|---------|------------|---------|-------|----------|")
        for dep in sorted(shipping, key=lambda d: (d.group_id, d.artifact_id)):
            version = dep.version or "—"
            scope = dep.scope or "compile"
            lines.append(f"| `{dep.group_id}` | `{dep.artifact_id}` | {version} | {scope} | `{dep.pom_path}:{dep.line_number}` |")

    if non_shipping:
        lines.append("")
        lines.append(f"### Non-shipping dependencies ({len(non_shipping)})")
        lines.append("")
        lines.append("These are test/provided scope — not shipped in the binary but still reveal internal infrastructure.")
        lines.append("")
        lines.append("| groupId | artifactId | Version | Scope | Found in |")
        lines.append("|---------|------------|---------|-------|----------|")
        for dep in sorted(non_shipping, key=lambda d: (d.group_id, d.artifact_id)):
            version = dep.version or "—"
            scope = dep.scope or "compile"
            lines.append(f"| `{dep.group_id}` | `{dep.artifact_id}` | {version} | {scope} | `{dep.pom_path}:{dep.line_number}` |")

    return "\n".join(lines)
