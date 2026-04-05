"""POM XML parsing helpers — coordinate, parent, and dependency extraction."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import NamedTuple

from .dependencies import PomDependency


class ParseCtx(NamedTuple):
    ns: str
    lines: list[str]
    rel_path: str


def _text(elem: ET.Element | None) -> str | None:
    return elem.text.strip() if elem is not None and elem.text else None


def extract_coordinates(root: ET.Element, ns: str, model) -> None:
    props_elem = root.find(f"{ns}properties")
    if props_elem is not None:
        for prop in props_elem:
            if prop.text:
                model.properties[prop.tag.replace(ns, "")] = prop.text.strip()

    version = _text(root.find(f"{ns}version"))
    if version:
        model.version = version
        model.properties["project.version"] = version

    gid = _text(root.find(f"{ns}groupId"))
    if gid:
        model.group_id = gid

    aid = _text(root.find(f"{ns}artifactId"))
    if aid:
        model.artifact_id = aid


def extract_parent(root: ET.Element, ns: str, model) -> None:
    parent = root.find(f"{ns}parent")
    if parent is None:
        return
    pgid = _text(parent.find(f"{ns}groupId"))
    paid = _text(parent.find(f"{ns}artifactId"))
    pver = _text(parent.find(f"{ns}version"))
    if pgid:
        model.parent_group_id = pgid
    if paid:
        model.parent_artifact_id = paid
    if pver:
        model.parent_version = pver


def line_of(lines: list[str], group_id: str, artifact_id: str) -> int:
    joined = "\n".join(lines)
    for i, line in enumerate(lines, 1):
        if artifact_id in line and group_id in joined:
            return i
    return 1


def _make_dependency(dep_elem: ET.Element, ctx: ParseCtx, model) -> PomDependency | None:
    gid_elem = dep_elem.find(f"{ctx.ns}groupId")
    aid_elem = dep_elem.find(f"{ctx.ns}artifactId")
    if gid_elem is None or aid_elem is None:
        return None
    group_id = model.resolve_property(gid_elem.text) or ""
    artifact_id = model.resolve_property(aid_elem.text) or ""
    ver_elem = dep_elem.find(f"{ctx.ns}version")
    scope_elem = dep_elem.find(f"{ctx.ns}scope")
    return PomDependency(
        group_id=group_id,
        artifact_id=artifact_id,
        version=model.resolve_property(ver_elem.text if ver_elem is not None else None),
        scope=scope_elem.text.strip() if scope_elem is not None and scope_elem.text else None,
        pom_path=ctx.rel_path,
        line_number=line_of(ctx.lines, group_id, artifact_id),
    )


def extract_dependencies(root: ET.Element, ctx: ParseCtx, model) -> None:
    for dep_elem in root.iter(f"{ctx.ns}dependency"):
        dep = _make_dependency(dep_elem, ctx, model)
        if dep is not None:
            model.dependencies.append(dep)

    parent = root.find(f"{ctx.ns}parent")
    if parent is not None and model.parent_group_id and model.parent_artifact_id:
        model.dependencies.append(PomDependency(
            group_id=model.parent_group_id,
            artifact_id=model.parent_artifact_id,
            version=model.parent_version,
            scope="parent",
            pom_path=ctx.rel_path,
            line_number=line_of(ctx.lines, model.parent_group_id, model.parent_artifact_id),
        ))
