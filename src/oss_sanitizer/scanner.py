"""Core scanner that orchestrates all detection modules."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import git

from .config import Config
from .models import Finding, ScanReport
from .scanners import secrets, urls, algorithms, dependencies

logger = logging.getLogger(__name__)


def _should_skip(file_path: str, config: Config) -> bool:
    """Check if a file should be skipped based on extension or path."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext in config.patterns.skip_extensions:
        return True
    for skip in config.patterns.skip_paths:
        if skip in file_path:
            return True
    return False


def _try_decode(data: bytes) -> str | None:
    """Try to decode bytes as text, return None if binary."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("latin-1")
        except UnicodeDecodeError:
            return None


def scan_working_tree(
    repo_path: Path,
    config: Config,
    progress_callback=None,
) -> list[Finding]:
    """Scan current working tree files."""
    findings: list[Finding] = []
    repo = git.Repo(repo_path)

    # Collect all tracked + untracked files
    tracked = set()
    for item in repo.tree().traverse():
        if item.type == "blob":
            tracked.add(item.path)

    # Also include untracked files
    for f in repo.untracked_files:
        tracked.add(f)

    total = len(tracked)
    for idx, file_path in enumerate(sorted(tracked)):
        if progress_callback:
            progress_callback(idx + 1, total, file_path)

        if _should_skip(file_path, config):
            continue

        full_path = repo_path / file_path
        if not full_path.is_file():
            continue

        # Skip large files
        if full_path.stat().st_size > config.max_file_size_kb * 1024:
            continue

        try:
            content = full_path.read_bytes()
        except (OSError, PermissionError):
            continue

        text = _try_decode(content)
        if text is None:
            continue

        # Run all scanners
        findings.extend(secrets.scan_for_secrets(text, file_path, config))
        findings.extend(urls.scan_for_internal_references(text, file_path, config))
        findings.extend(algorithms.scan_for_sensitive_algorithms(text, file_path, config))

    return findings


def scan_git_history(
    repo_path: Path,
    config: Config,
    progress_callback=None,
) -> list[Finding]:
    """Scan all unique blobs across git history."""
    findings: list[Finding] = []
    repo = git.Repo(repo_path)

    # Build a map: blob_sha -> (file_path, last_commit_sha)
    # Walk all commits to find the LAST commit each blob appeared in
    blob_map: dict[str, tuple[str, str]] = {}  # blob_sha -> (path, commit_sha)

    logger.info("Building blob map from git history...")
    commits = sorted(repo.iter_commits("--all"), key=lambda c: c.committed_date, reverse=True)
    total_commits = len(commits)

    for commit_idx, commit in enumerate(commits):
        if progress_callback:
            progress_callback(commit_idx + 1, total_commits, f"commit {commit.hexsha[:8]}")

        try:
            for item in commit.tree.traverse():
                if item.type != "blob":
                    continue
                blob_sha = item.hexsha
                # We iterate newest-first, so first occurrence = last commit
                if blob_sha not in blob_map:
                    blob_map[blob_sha] = (item.path, commit.hexsha)
        except Exception as e:
            logger.warning(f"Error traversing commit {commit.hexsha[:8]}: {e}")
            continue

    logger.info(f"Found {len(blob_map)} unique blobs across {total_commits} commits")

    # Now scan each unique blob
    total_blobs = len(blob_map)
    for idx, (blob_sha, (file_path, commit_sha)) in enumerate(blob_map.items()):
        if progress_callback:
            progress_callback(idx + 1, total_blobs, file_path)

        if _should_skip(file_path, config):
            continue

        try:
            blob = repo.git.show(blob_sha)
            if isinstance(blob, str):
                text = blob
            else:
                text = _try_decode(blob)
                if text is None:
                    continue
        except Exception:
            continue

        # Skip large blobs
        if len(text) > config.max_file_size_kb * 1024:
            continue

        findings.extend(secrets.scan_for_secrets(text, file_path, config, commit_sha))
        findings.extend(urls.scan_for_internal_references(text, file_path, config, commit_sha))
        findings.extend(algorithms.scan_for_sensitive_algorithms(text, file_path, config, commit_sha))

    return findings


def scan(
    repo_path: str | Path,
    config: Config,
    progress_callback=None,
) -> ScanReport:
    """Run a full scan on a repository."""
    repo_path = Path(repo_path)
    report = ScanReport(repo_path=str(repo_path), scan_history=config.scan_history)

    # Always scan working tree
    logger.info("Scanning working tree...")
    report.add_findings(scan_working_tree(repo_path, config, progress_callback))

    # Optionally scan history
    if config.scan_history:
        logger.info("Scanning git history...")
        report.add_findings(scan_git_history(repo_path, config, progress_callback))

    # Scan for internal Maven dependencies
    logger.info("Scanning for internal dependencies...")
    report.internal_dependencies = dependencies.find_internal_dependencies(repo_path, config)

    return report
