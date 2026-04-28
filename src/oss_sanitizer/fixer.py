"""Replacement map builder and file fixer for --fix mode."""

from __future__ import annotations

from pathlib import Path

import yaml

from .models import Finding, FindingType
from .scrubber import Scrubber

_HOST_TYPES = frozenset({FindingType.INTERNAL_URL, FindingType.INTERNAL_HOSTNAME})
_SECRET_TYPES = frozenset({FindingType.SECRET})


def make_scrubbers(findings: list[Finding]) -> list[Scrubber]:
    """Create and register the two application scrubbers from a finding list."""
    hostname = Scrubber("HOST", _HOST_TYPES)
    secret = Scrubber("SECRET", _SECRET_TYPES)
    hostname.register(findings)
    secret.register(findings)
    return [hostname, secret]


def write_replacement_map(replacement_map: dict[str, str], path: Path) -> None:
    """Write {token: original} YAML so developers can review what was replaced."""
    inverted = {token: original for original, token in replacement_map.items()}
    path.write_text(yaml.dump(inverted, default_flow_style=False, sort_keys=True, allow_unicode=True))


def apply_fixes(findings: list[Finding], scrubbers: list[Scrubber], repo_path: Path | None = None) -> None:
    """Apply scrubbers to each file referenced by findings that have a match_value."""
    file_paths = {f.file_path for f in findings if f.match_value is not None}
    for file_path in file_paths:
        path = repo_path / file_path if repo_path else Path(file_path)
        text = path.read_text(encoding="utf-8")
        for scrubber in scrubbers:
            text = scrubber.scrub(text)
        path.write_text(text, encoding="utf-8")
