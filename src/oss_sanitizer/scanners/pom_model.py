"""Structured representation of a Maven POM file.

Parsed once and consumed by both the dependency scanner and the URL/hostname
scanner. Avoids duplicating XML parsing logic across modules.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class SectionRole(Enum):
    SKIP = "skip"        # coordinates — never flag
    HIGH = "high"        # repository URLs, SCM — full confidence
    MEDIUM = "medium"    # properties, configuration — moderate confidence
    DEFAULT = "default"  # everything else


# Score factors per role
ROLE_FACTORS: dict[SectionRole, float | None] = {
    SectionRole.SKIP: None,
    SectionRole.HIGH: 1.0,
    SectionRole.MEDIUM: 0.8,
    SectionRole.DEFAULT: 0.5,
}

# Leaf tags whose lines should always be skipped
_SKIP_LEAF_TAGS = re.compile(
    r"<\s*(?:groupId|artifactId|version|packaging|modelVersion|module"
    r"|scope|type|classifier|systemPath|relativePath)\s*>"
)

_HIGH_PARENTS = frozenset({
    "repository", "snapshotRepository", "pluginRepository",
    "distributionManagement", "scm", "ciManagement",
    "issueManagement", "mailingList",
})
_MEDIUM_PARENTS = frozenset({
    "properties", "configuration", "profile", "build",
    "plugins", "plugin", "execution",
})
_SKIP_PARENTS = frozenset({
    "dependency", "dependencies", "parent", "exclusion", "exclusions",
})

_OPEN_TAG = re.compile(r"<\s*([a-zA-Z][\w.-]*)\s*[^/]*?>")
_CLOSE_TAG = re.compile(r"</\s*([a-zA-Z][\w.-]*)\s*>")
_SELF_CLOSING = re.compile(r"<\s*([a-zA-Z][\w.-]*)\s*[^>]*/\s*>")
_HIGH_TAGS_INLINE = re.compile(
    r"<\s*(?:url|connection|developerConnection|downloadUrl"
    r"|wsdlLocation|endpoint|baseUrl|serverUrl|host|address)\s*>"
)


_NON_SHIPPING_SCOPES = frozenset({"test", "provided", "system"})


@dataclass
class PomDependency:
    group_id: str
    artifact_id: str
    version: str | None
    scope: str | None
    pom_path: str
    line_number: int

    @property
    def is_shipping(self) -> bool:
        """A dependency ships in the binary unless its scope is test/provided/system."""
        return (self.scope or "compile") not in _NON_SHIPPING_SCOPES


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
        """Return the score factor (0–1) for the given 1-based line number.
        Returns None to indicate the line should be completely skipped.
        """
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
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    model = PomModel(path=rel_path)

    # ── Properties ─────────────────────────────────────────────────────
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

    # ── Parent ─────────────────────────────────────────────────────────
    parent = root.find(f"{ns}parent")
    if parent is not None:
        pgid = parent.find(f"{ns}groupId")
        paid = parent.find(f"{ns}artifactId")
        pver = parent.find(f"{ns}version")
        if pgid is not None and pgid.text:
            model.parent_group_id = pgid.text.strip()
        if paid is not None and paid.text:
            model.parent_artifact_id = paid.text.strip()
        if pver is not None and pver.text:
            model.parent_version = pver.text.strip()

    # ── Dependencies ───────────────────────────────────────────────────
    lines = pom_text.splitlines()

    def _line_of(group_id: str, artifact_id: str) -> int:
        for i, line in enumerate(lines, 1):
            if artifact_id in line:
                ctx = "\n".join(lines[max(0, i - 3):i + 3])
                if group_id in ctx:
                    return i
        return 1

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
            line_number=_line_of(group_id, artifact_id),
        ))

    if parent is not None and model.parent_group_id and model.parent_artifact_id:
        model.dependencies.append(PomDependency(
            group_id=model.parent_group_id,
            artifact_id=model.parent_artifact_id,
            version=model.parent_version,
            scope="parent",
            pom_path=rel_path,
            line_number=_line_of(model.parent_group_id, model.parent_artifact_id),
        ))

    # ── Line role map ──────────────────────────────────────────────────
    model._line_roles = _build_line_roles(pom_text)

    return model


def _build_line_roles(pom_text: str) -> list[SectionRole | None]:
    """Walk the POM line-by-line building a per-line SectionRole."""
    lines = pom_text.splitlines()
    roles: list[SectionRole | None] = []
    stack: list[str] = []

    for line in lines:
        stripped = line.strip()

        if _SKIP_LEAF_TAGS.search(stripped):
            roles.append(None)
        else:
            role: SectionRole | None = SectionRole.DEFAULT
            for tag in reversed(stack):
                if tag in _SKIP_PARENTS:
                    role = None
                    break
                if tag in _HIGH_PARENTS:
                    role = SectionRole.HIGH
                    break
                if tag in _MEDIUM_PARENTS:
                    role = SectionRole.MEDIUM
                    break
            if role is not None and _HIGH_TAGS_INLINE.search(stripped):
                role = SectionRole.HIGH
            roles.append(role)

        if not _SELF_CLOSING.search(stripped):
            for m in _OPEN_TAG.finditer(stripped):
                stack.append(m.group(1))
            for m in _CLOSE_TAG.finditer(stripped):
                tag = m.group(1)
                while stack and stack[-1] != tag:
                    stack.pop()
                if stack:
                    stack.pop()

    return roles
