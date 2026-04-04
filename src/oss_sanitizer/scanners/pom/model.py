"""Structured representation of a Maven POM file."""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from .dependencies import PomDependency
from .line_roles import ROLE_FACTORS, SectionRole, build_line_roles

logger = logging.getLogger(__name__)


@dataclass
class PomModel:
    """All structured information from a single pom.xml."""

    path: str
    group_id: str = ""
    artifact_id: str = ""
    version: str | None = None
    parent_group_id: str = ""
    parent_artifact_id: str = ""
    parent_version: str | None = None
    properties: dict[str, str] = field(default_factory=dict)
    dependencies: list[PomDependency] = field(default_factory=list)
    _line_roles: list[SectionRole | None] = field(default_factory=list, repr=False)

    def score_factor_for_line(self, line_number: int) -> float | None:
        """Return the score factor (0–1) for the given 1-based line number."""
        idx = line_number - 1
        if idx < 0 or idx >= len(self._line_roles):
            return ROLE_FACTORS[SectionRole.DEFAULT]
        role = self._line_roles[idx]
        if role is None:
            return None
        return ROLE_FACTORS[role]

    def resolve_property(self, value: str | None) -> str | None:
        """Resolve Maven ${property} references from this POM's properties."""
        if value is None:
            return None
        m = re.match(r"\$\{(.+)\}", value)
        if m:
            return self.properties.get(m.group(1), value)
        return value


def parse_from_text(pom_text: str, rel_path: str = "pom.xml") -> PomModel | None:
    """Parse a POM from an in-memory string (useful for testing)."""
    try:
        root = ET.fromstring(pom_text)
    except ET.ParseError as e:
        logger.warning(f"Failed to parse {rel_path}: {e}")
        return None
    return _build_model(root, pom_text, rel_path)


def parse(pom_path: Path, repo_path: Path) -> PomModel | None:
    """Parse a pom.xml from disk and return a PomModel, or None on failure."""
    try:
        pom_text = pom_path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning(f"Failed to read {pom_path}: {e}")
        return None
    try:
        root = ET.fromstring(pom_text)
    except ET.ParseError as e:
        logger.warning(f"Failed to parse {pom_path}: {e}")
        return None
    rel_path = str(pom_path.relative_to(repo_path))
    return _build_model(root, pom_text, rel_path)


def _build_model(root: ET.Element, pom_text: str, rel_path: str) -> PomModel:
    ns = "" if not root.tag.startswith("{") else root.tag.split("}")[0] + "}"
    model = PomModel(path=rel_path)
    _extract_coordinates(root, ns, model)
    _extract_parent(root, ns, model)
    _extract_dependencies(root, ns, model, pom_text.splitlines(), rel_path)
    model._line_roles = build_line_roles(pom_text)
    return model


def _extract_coordinates(root: ET.Element, ns: str, model: PomModel) -> None:
    props_elem = root.find(f"{ns}properties")
    if props_elem is not None:
        for prop in props_elem:
            tag = prop.tag.replace(ns, "")
            if prop.text:
                model.properties[tag] = prop.text.strip()

    ver_elem = root.find(f"{ns}version")
    if ver_elem is not None and ver_elem.text:
        model.version = ver_elem.text.strip()
        model.properties["project.version"] = model.version

    gid_elem = root.find(f"{ns}groupId")
    if gid_elem is not None and gid_elem.text:
        model.group_id = gid_elem.text.strip()

    aid_elem = root.find(f"{ns}artifactId")
    if aid_elem is not None and aid_elem.text:
        model.artifact_id = aid_elem.text.strip()


def _extract_parent(root: ET.Element, ns: str, model: PomModel) -> None:
    parent = root.find(f"{ns}parent")
    if parent is None:
        return
    pgid = parent.find(f"{ns}groupId")
    paid = parent.find(f"{ns}artifactId")
    pver = parent.find(f"{ns}version")
    if pgid is not None and pgid.text:
        model.parent_group_id = pgid.text.strip()
    if paid is not None and paid.text:
        model.parent_artifact_id = paid.text.strip()
    if pver is not None and pver.text:
        model.parent_version = pver.text.strip()


def _line_of(lines: list[str], group_id: str, artifact_id: str) -> int:
    for i, line in enumerate(lines, 1):
        if artifact_id in line:
            ctx = "\n".join(lines[max(0, i - 3):i + 3])
            if group_id in ctx:
                return i
    return 1


def _extract_dependencies(
    root: ET.Element,
    ns: str,
    model: PomModel,
    lines: list[str],
    rel_path: str,
) -> None:
    for dep_elem in root.iter(f"{ns}dependency"):
        gid = dep_elem.find(f"{ns}groupId")
        aid = dep_elem.find(f"{ns}artifactId")
        if gid is None or aid is None:
            continue
        group_id = model.resolve_property(gid.text) or ""
        artifact_id = model.resolve_property(aid.text) or ""
        ver = dep_elem.find(f"{ns}version")
        version = model.resolve_property(ver.text if ver is not None else None)
        scope_elem = dep_elem.find(f"{ns}scope")
        scope = scope_elem.text.strip() if scope_elem is not None and scope_elem.text else None
        model.dependencies.append(PomDependency(
            group_id=group_id,
            artifact_id=artifact_id,
            version=version,
            scope=scope,
            pom_path=rel_path,
            line_number=_line_of(lines, group_id, artifact_id),
        ))

    parent = root.find(f"{ns}parent")
    if parent is not None and model.parent_group_id and model.parent_artifact_id:
        model.dependencies.append(PomDependency(
            group_id=model.parent_group_id,
            artifact_id=model.parent_artifact_id,
            version=model.parent_version,
            scope="parent",
            pom_path=rel_path,
            line_number=_line_of(lines, model.parent_group_id, model.parent_artifact_id),
        ))
