"""Internal dependency detection from Maven pom.xml files."""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from ..config import Config

logger = logging.getLogger(__name__)

# Maven POM namespace
NS = {"m": "http://maven.apache.org/POM/4.0.0"}

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


def _get_line_number(pom_text: str, group_id: str, artifact_id: str) -> int:
    """Find the approximate line number of a dependency in pom.xml."""
    lines = pom_text.splitlines()
    for i, line in enumerate(lines, 1):
        if artifact_id in line:
            # Check nearby lines for the groupId to confirm it's the right one
            context = "\n".join(lines[max(0, i - 3):i + 3])
            if group_id in context:
                return i
    return 1


def _resolve_property(value: str | None, properties: dict[str, str]) -> str | None:
    """Resolve Maven ${property} references."""
    if value is None:
        return None
    match = re.match(r"\$\{(.+)\}", value)
    if match:
        prop_name = match.group(1)
        return properties.get(prop_name, value)
    return value


def parse_pom(pom_path: Path, repo_path: Path) -> list[Dependency]:
    """Parse a pom.xml and extract all dependencies."""
    dependencies: list[Dependency] = []
    rel_path = str(pom_path.relative_to(repo_path))

    try:
        pom_text = pom_path.read_text(encoding="utf-8")
        tree = ET.parse(pom_path)
    except (ET.ParseError, OSError) as e:
        logger.warning(f"Failed to parse {rel_path}: {e}")
        return []

    root = tree.getroot()

    # Detect namespace
    ns = ""
    root_tag = root.tag
    if root_tag.startswith("{"):
        ns = root_tag.split("}")[0] + "}"

    # Collect properties for variable resolution
    properties: dict[str, str] = {}
    props_elem = root.find(f"{ns}properties")
    if props_elem is not None:
        for prop in props_elem:
            tag = prop.tag.replace(ns, "")
            if prop.text:
                properties[tag] = prop.text.strip()

    # Also grab parent version / project version
    version_elem = root.find(f"{ns}version")
    if version_elem is not None and version_elem.text:
        properties["project.version"] = version_elem.text.strip()

    # Find all <dependency> elements (in dependencies and dependencyManagement)
    for dep_elem in root.iter(f"{ns}dependency"):
        gid_elem = dep_elem.find(f"{ns}groupId")
        aid_elem = dep_elem.find(f"{ns}artifactId")

        if gid_elem is None or aid_elem is None:
            continue

        group_id = _resolve_property(gid_elem.text, properties) or ""
        artifact_id = _resolve_property(aid_elem.text, properties) or ""

        ver_elem = dep_elem.find(f"{ns}version")
        version = _resolve_property(ver_elem.text if ver_elem is not None else None, properties)

        scope_elem = dep_elem.find(f"{ns}scope")
        scope = scope_elem.text.strip() if scope_elem is not None and scope_elem.text else None

        line_number = _get_line_number(pom_text, group_id, artifact_id)

        dependencies.append(Dependency(
            group_id=group_id,
            artifact_id=artifact_id,
            version=version,
            scope=scope,
            pom_path=rel_path,
            line_number=line_number,
        ))

    # Also extract parent if present
    parent = root.find(f"{ns}parent")
    if parent is not None:
        gid_elem = parent.find(f"{ns}groupId")
        aid_elem = parent.find(f"{ns}artifactId")
        if gid_elem is not None and aid_elem is not None:
            group_id = gid_elem.text or ""
            artifact_id = aid_elem.text or ""
            ver_elem = parent.find(f"{ns}version")
            version = ver_elem.text if ver_elem is not None else None
            line_number = _get_line_number(pom_text, group_id, artifact_id)
            dependencies.append(Dependency(
                group_id=group_id,
                artifact_id=artifact_id,
                version=version,
                scope="parent",
                pom_path=rel_path,
                line_number=line_number,
            ))

    return dependencies


def find_internal_dependencies(
    repo_path: Path,
    config: Config,
    project_group_ids: set[str] | None = None,
) -> list[Dependency]:
    """Find all internal dependencies across all pom.xml files.

    A dependency is considered internal if:
    1. Its groupId matches an internal pattern (e.g., ch.ge.*), AND
    2. It is NOT a module of the project being analyzed (based on groupIds found in the repo's own pom files).
    """
    poms = _find_pom_files(repo_path, config)
    if not poms:
        return []

    # First pass: collect all groupIds defined in this project's own pom files
    if project_group_ids is None:
        project_group_ids = set()
        for pom_path in poms:
            try:
                tree = ET.parse(pom_path)
                root = tree.getroot()
                ns = ""
                if root.tag.startswith("{"):
                    ns = root.tag.split("}")[0] + "}"
                gid = root.find(f"{ns}groupId")
                if gid is not None and gid.text:
                    project_group_ids.add(gid.text.strip())
                # Also check parent groupId (often inherited)
                parent = root.find(f"{ns}parent")
                if parent is not None:
                    pgid = parent.find(f"{ns}groupId")
                    if pgid is not None and pgid.text:
                        project_group_ids.add(pgid.text.strip())
            except (ET.ParseError, OSError):
                continue

    logger.info(f"Project groupIds: {project_group_ids}")

    # Compile internal patterns
    internal_patterns = [
        re.compile(p) for p in DEFAULT_INTERNAL_GROUP_PATTERNS
    ]
    # Add any extra patterns from config (future extensibility)

    # Second pass: collect all dependencies and filter
    all_deps: list[Dependency] = []
    for pom_path in poms:
        all_deps.extend(parse_pom(pom_path, repo_path))

    # Filter to internal deps not in the project itself
    internal: list[Dependency] = []
    seen = set()
    for dep in all_deps:
        if not any(p.search(dep.group_id) for p in internal_patterns):
            continue
        # Skip if it's part of this project
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
    lines.append("| groupId | artifactId | Version | Scope | Found in |")
    lines.append("|---------|------------|---------|-------|----------|")

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
