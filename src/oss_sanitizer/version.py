"""Resolve the tool's own version and build commit for report traceability."""

from __future__ import annotations

import subprocess
from functools import lru_cache
from importlib.metadata import version as pkg_version
from pathlib import Path


@lru_cache(maxsize=1)
def get_version() -> str:
    """Package version from metadata (pyproject.toml)."""
    try:
        return pkg_version("oss-sanitizer")
    except Exception:
        return "unknown"


@lru_cache(maxsize=1)
def get_commit() -> str:
    """Git commit SHA of the oss-sanitizer installation.

    Works when running from a git checkout (development or pip install -e).
    Returns 'unknown' for standalone wheel installs.
    """
    pkg_dir = Path(__file__).resolve().parent
    # Walk up to find a .git directory (covers src layout)
    for ancestor in [pkg_dir, *pkg_dir.parents]:
        if (ancestor / ".git").exists():
            try:
                result = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=ancestor,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    return result.stdout.strip()
            except Exception:
                pass
            break
    return "unknown"
