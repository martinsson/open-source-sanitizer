"""Replacement map builder and file fixer for --fix mode."""

from __future__ import annotations

from pathlib import Path

import yaml

from .models import Finding, FindingType

_HOST_TYPES = {FindingType.INTERNAL_URL, FindingType.INTERNAL_HOSTNAME}


def build_replacement_map(findings: list[Finding]) -> dict[str, str]:
    """Return {original_value: token} for all findings that have a match_value."""
    host_counter = 0
    secret_counter = 0
    result: dict[str, str] = {}

    for finding in findings:
        value = finding.match_value
        if value is None or value in result:
            continue
        if finding.finding_type in _HOST_TYPES:
            host_counter += 1
            result[value] = f"HOST_{host_counter}"
        elif finding.finding_type == FindingType.SECRET:
            secret_counter += 1
            result[value] = f"SECRET_{secret_counter}"

    return result


def write_replacement_map(replacement_map: dict[str, str], path: Path) -> None:
    """Write {token: original} YAML so developers can review what was replaced."""
    inverted = {token: original for original, token in replacement_map.items()}
    path.write_text(yaml.dump(inverted, default_flow_style=False, sort_keys=True, allow_unicode=True))


def apply_fixes(findings: list[Finding], replacement_map: dict[str, str], repo_path: Path | None = None) -> None:
    """Apply replacement_map to each file referenced by findings."""
    files_to_fix: dict[str, set[str]] = {}
    for finding in findings:
        if finding.match_value and finding.match_value in replacement_map:
            files_to_fix.setdefault(finding.file_path, set()).add(finding.match_value)

    for file_path, values in files_to_fix.items():
        path = repo_path / file_path if repo_path else Path(file_path)
        text = path.read_text(encoding="utf-8")
        for value in values:
            text = text.replace(value, replacement_map[value])
        path.write_text(text, encoding="utf-8")
