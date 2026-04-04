"""Git history scanner — scans all unique blobs across git commits."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import git

from .config import Config
from .models import Finding
from .scanners import algorithms, secrets, urls

logger = logging.getLogger(__name__)


def should_skip(file_path: str, config: Config) -> bool:
    """Check if a file should be skipped based on extension or path."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext in config.patterns.skip_extensions:
        return True
    return any(skip in file_path for skip in config.patterns.skip_paths)


def try_decode(data: bytes) -> str | None:
    """Try to decode bytes as text, return None if binary."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("latin-1")
        except UnicodeDecodeError:
            return None


def scan_git_history(
    repo_path: Path,
    config: Config,
    progress_callback=None,
) -> list[Finding]:
    """Scan all unique blobs across git history."""
    findings: list[Finding] = []
    repo = git.Repo(repo_path)

    blob_map = _build_blob_map(repo, progress_callback)
    logger.info(f"Found {len(blob_map)} unique blobs across history")

    total_blobs = len(blob_map)
    for idx, (blob_sha, (file_path, commit_sha)) in enumerate(blob_map.items()):
        if progress_callback:
            progress_callback(idx + 1, total_blobs, file_path)

        if should_skip(file_path, config):
            continue

        text = _read_blob(repo, blob_sha)
        if text is None or len(text) > config.max_file_size_kb * 1024:
            continue

        findings.extend(secrets.scan_for_secrets(text, file_path, config, commit_sha))
        findings.extend(urls.scan_for_internal_references(text, file_path, config, commit_sha))
        findings.extend(algorithms.scan_for_sensitive_algorithms(text, file_path, config, commit_sha))

    return findings


def _build_blob_map(repo: git.Repo, progress_callback) -> dict[str, tuple[str, str]]:
    """Build blob_sha → (file_path, commit_sha) map from newest to oldest commit."""
    blob_map: dict[str, tuple[str, str]] = {}
    commits = sorted(repo.iter_commits("--all"), key=lambda c: c.committed_date, reverse=True)
    total_commits = len(commits)

    for commit_idx, commit in enumerate(commits):
        if progress_callback:
            progress_callback(commit_idx + 1, total_commits, f"commit {commit.hexsha[:8]}")
        try:
            for item in commit.tree.traverse():
                if item.type == "blob" and item.hexsha not in blob_map:
                    blob_map[item.hexsha] = (item.path, commit.hexsha)
        except Exception as e:
            logger.warning(f"Error traversing commit {commit.hexsha[:8]}: {e}")

    return blob_map


def _read_blob(repo: git.Repo, blob_sha: str) -> str | None:
    try:
        blob = repo.git.show(blob_sha)
        if isinstance(blob, str):
            return blob
        return try_decode(blob)
    except Exception:
        return None
