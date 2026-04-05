"""Per-line section role detection for Maven POM files."""

from __future__ import annotations

import re
from enum import Enum


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


_TAG_ROLE = {
    **{t: None for t in _SKIP_PARENTS},
    **{t: SectionRole.HIGH for t in _HIGH_PARENTS},
    **{t: SectionRole.MEDIUM for t in _MEDIUM_PARENTS},
}


def _role_from_stack(stack: list[str]) -> SectionRole | None:
    """Walk the tag stack (innermost-first) to determine role for current line."""
    sentinel = object()
    for tag in reversed(stack):
        role = _TAG_ROLE.get(tag, sentinel)
        if role is not sentinel:
            return role  # type: ignore[return-value]
    return SectionRole.DEFAULT


def _update_tag_stack(stripped: str, stack: list[str]) -> None:
    """Update the XML tag stack based on open/close/self-closing tags on a line."""
    if _SELF_CLOSING.search(stripped):
        return
    for m in _OPEN_TAG.finditer(stripped):
        stack.append(m.group(1))
    for m in _CLOSE_TAG.finditer(stripped):
        tag = m.group(1)
        while stack and stack[-1] != tag:
            stack.pop()
        if stack:
            stack.pop()


def build_line_roles(pom_text: str) -> list[SectionRole | None]:
    """Walk the POM line-by-line building a per-line SectionRole."""
    lines = pom_text.splitlines()
    roles: list[SectionRole | None] = []
    stack: list[str] = []

    for line in lines:
        stripped = line.strip()
        if _SKIP_LEAF_TAGS.search(stripped):
            roles.append(None)
        else:
            role = _role_from_stack(stack)
            if role is not None and _HIGH_TAGS_INLINE.search(stripped):
                role = SectionRole.HIGH
            roles.append(role)
        _update_tag_stack(stripped, stack)

    return roles
