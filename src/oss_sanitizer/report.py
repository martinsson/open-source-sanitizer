"""Markdown report generator."""

from __future__ import annotations

from datetime import datetime, timezone

from jinja2 import Environment, PackageLoader, select_autoescape

from .models import FindingType, ScanReport
from .scanners.dependencies import render_dependency_report
from .version import get_commit, get_version

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
    rows = [heading, "", "| Category | Count | Score |", "|----------|------:|------:|"]
    for ftype in TYPE_ORDER:
        label, _ = TYPE_LABELS[ftype]
        items = grouped.get(ftype, [])
        rows.append(f"| {label} | {len(items)} | {sum(f.score for f in items):.1f} |")
    total = sum(len(grouped.get(ft, [])) for ft in TYPE_ORDER)
    total_score = sum(sum(f.score for f in grouped.get(ft, [])) for ft in TYPE_ORDER)
    rows.append(f"| **Total** | **{total}** | **{total_score:.1f}** |")
    return "\n".join(rows)


def _group_by_file(findings: list) -> list[tuple[str, list]]:
    by_file: dict[str, list] = {}
    for f in findings:
        by_file.setdefault(f.file_path, []).append(f)
    return list(by_file.items())


def _clean_output(result: str) -> str:
    lines = [line.rstrip() for line in result.splitlines()]
    cleaned: list[str] = []
    prev_blank = False
    for line in lines:
        is_blank = not line.strip()
        if not (is_blank and prev_blank):
            cleaned.append(line)
        prev_blank = is_blank
    return "\n".join(cleaned).rstrip() + "\n"


def _build_template_context(report: ScanReport) -> dict:
    grouped = report.findings_by_type()
    return {
        "report": report,
        "now": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "tool_version": get_version(),
        "tool_commit": get_commit(),
        "grouped": grouped,
        "grouped_by_file": {ft: _group_by_file(items) for ft, items in grouped.items()},
        "type_order": TYPE_ORDER,
        "labels": TYPE_LABELS,
        "summary_table": _summary_table,
        "deps_report": render_dependency_report(report.internal_dependencies, report.repo_path) if report.internal_dependencies else "",
    }


def render_markdown(report: ScanReport) -> str:
    """Render a ScanReport as a Markdown document."""
    ctx = _build_template_context(report)
    result = _env.get_template("report.md.j2").render(**ctx)
    return _clean_output(result)
