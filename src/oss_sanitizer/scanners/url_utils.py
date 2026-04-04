"""Shared URL scanning utilities: patterns, snippet builder, explanations."""

from __future__ import annotations

import os
import re

# General URL pattern
URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9][-a-zA-Z0-9_.]*(?::\d+)?(?:/[^\s'\")><\]]*)?",
)

_PROPERTIES_EXTS = {".properties", ".cfg", ".ini", ".env", ".conf"}

_PROPERTIES_BASENAMES = frozenset({
    ".env", "application.yml", "application.yaml",
    "application.properties", "bootstrap.yml", "bootstrap.yaml",
})

# Compiled pattern cache: patterns come from Config, don't change per-file.
_pattern_cache: dict[tuple, list[re.Pattern]] = {}


def is_pom_file(file_path: str) -> bool:
    """Only pom.xml files get Maven-aware context scoring."""
    return os.path.basename(file_path).lower() == "pom.xml"


def is_properties_file(file_path: str) -> bool:
    ext = os.path.splitext(file_path)[1].lower()
    base = os.path.basename(file_path).lower()
    return ext in _PROPERTIES_EXTS or base in _PROPERTIES_BASENAMES


def compile_patterns(raw: list[str]) -> list[re.Pattern]:
    key = tuple(raw)
    if key not in _pattern_cache:
        _pattern_cache[key] = [re.compile(p) for p in raw]
    return _pattern_cache[key]


def make_snippet(lines: list[str], line_idx: int) -> str:
    start = max(0, line_idx - 3)
    end = min(len(lines), line_idx + 2)
    snippet_lines = lines[start:end]
    return "\n".join(
        f"{start + i + 1:>4} | {l}" for i, l in enumerate(snippet_lines)
    )


def url_explanation(factor: float) -> str:
    base = "Internal URLs must be removed before publication per Charte §2 (Confidentialité)."
    if factor < 1.0:
        base += f" (reduced confidence — score factor {factor:.0%} based on XML context)"
    return base


def hostname_explanation(factor: float) -> str:
    base = "Internal hostnames/server names must be removed per Charte §2 (Confidentialité)."
    if factor < 1.0:
        base += f" (reduced confidence — score factor {factor:.0%} based on XML context)"
    return base
