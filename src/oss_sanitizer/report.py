"""Markdown report generator."""

from __future__ import annotations

from datetime import datetime, timezone

from jinja2 import Environment, PackageLoader, select_autoescape

from .models import FindingType, ScanReport
from .scanners.dependencies import render_dependency_report
from .version import get_version, get_commit

TYPE_LABELS = {
    FindingType.SECRET: ("Secrets & Credentials", "Hardcoded secrets, API keys, passwords, tokens, and private keys."),
    FindingType.INTERNAL_URL: ("Internal URLs", "URLs pointing to internal government infrastructure."),
    FindingType.INTERNAL_HOSTNAME: ("Internal Hostnames", "Server names and internal infrastructure identifiers."),
    FindingType.SENSITIVE_ALGORITHM: ("Sensitive Algorithms", "Government-specific business logic that may require review before publication."),
}

TYPE_ORDER = [
    FindingType.SECRET,
    FindingType.INTERNAL_URL,
    FindingType.INTERNAL_HOSTNAME,
    FindingType.SENSITIVE_ALGORITHM,
]

_env = Environment(
    loader=PackageLoader("oss_sanitizer", "templates"),
    autoescape=select_autoescape([]),
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


def _summary_table(grouped: dict, heading: str = "## Summary") -> str:
    lines = [
        heading, "",
        "| Category | Count | Score |",
        "|----------|------:|------:|",
    ]
    for ftype in TYPE_ORDER:
        label, _ = TYPE_LABELS[ftype]
        items = grouped.get(ftype, [])
        score = sum(f.score for f in items)
        lines.append(f"| {label} | {len(items)} | {score:.1f} |")
    total_findings = sum(len(grouped.get(ft, [])) for ft in TYPE_ORDER)
    total_score = sum(sum(f.score for f in grouped.get(ft, [])) for ft in TYPE_ORDER)
    lines.append(f"| **Total** | **{total_findings}** | **{total_score:.1f}** |")
    return "\n".join(lines)


def _group_by_file(findings: list) -> list[tuple[str, list]]:
    """Group findings by file path, preserving insertion order."""
    by_file: dict[str, list] = {}
    for f in findings:
        by_file.setdefault(f.file_path, []).append(f)
    return list(by_file.items())


def render_markdown(report: ScanReport) -> str:
    """Render a ScanReport as a Markdown document."""
    grouped = report.findings_by_type()

    # Pre-group each finding type by file for the template
    grouped_by_file = {
        ftype: _group_by_file(items)
        for ftype, items in grouped.items()
    }

    tool_version = get_version()
    tool_commit = get_commit()

    template = _env.get_template("report.md.j2")
    result = template.render(
        report=report,
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        tool_version=tool_version,
        tool_commit=tool_commit,
        grouped=grouped,
        grouped_by_file=grouped_by_file,
        type_order=TYPE_ORDER,
        labels=TYPE_LABELS,
        summary_table=_summary_table,
        deps_report=render_dependency_report(report.internal_dependencies, report.repo_path)
        if report.internal_dependencies else "",
    )
    # Strip trailing whitespace on each line for clean output
    lines = [line.rstrip() for line in result.splitlines()]
    # Remove consecutive blank lines (Jinja block tags can produce them)
    cleaned: list[str] = []
    prev_blank = False
    for line in lines:
        is_blank = not line.strip()
        if is_blank and prev_blank:
            continue
        cleaned.append(line)
        prev_blank = is_blank
    return "\n".join(cleaned).rstrip() + "\n"
