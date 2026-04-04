"""Structured representation of a Maven POM file."""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from .dependencies import PomDependency
from .line_roles import ROLE_FACTORS, SectionRole, build_line_roles
from .parser import ParseCtx, extract_coordinates, extract_dependencies, extract_parent

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
        return None if role is None else ROLE_FACTORS[role]

    def resolve_property(self, value: str | None) -> str | None:
        """Resolve Maven ${property} references from this POM's properties."""
        if value is None:
            return None
        m = re.match(r"\$\{(.+)\}", value)
        return self.properties.get(m.group(1), value) if m else value


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
    return _build_model(root, pom_text, str(pom_path.relative_to(repo_path)))


def _build_model(root: ET.Element, pom_text: str, rel_path: str) -> PomModel:
    ns = "" if not root.tag.startswith("{") else root.tag.split("}")[0] + "}"
    model = PomModel(path=rel_path)
    extract_coordinates(root, ns, model)
    extract_parent(root, ns, model)
    extract_dependencies(root, ParseCtx(ns=ns, lines=pom_text.splitlines(), rel_path=rel_path), model)
    model._line_roles = build_line_roles(pom_text)
    return model
