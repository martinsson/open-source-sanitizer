"""Core scanner that orchestrates all detection modules."""

from __future__ import annotations

import logging
from pathlib import Path

import git

from .config import Config
from .models import Finding, ScanReport
from .scanner_history import scan_git_history, should_skip, try_decode
from .scanners import algorithms, dependencies, secrets, urls

logger = logging.getLogger(__name__)


def scan_working_tree(
    repo_path: Path,
    config: Config,
    progress_callback=None,
) -> list[Finding]:
    """Scan current working tree files."""
    findings: list[Finding] = []
    repo = git.Repo(repo_path)

    tracked = {item.path for item in repo.tree().traverse() if item.type == "blob"}
    tracked.update(repo.untracked_files)

    total = len(tracked)
    for idx, file_path in enumerate(sorted(tracked)):
        if progress_callback:
            progress_callback(idx + 1, total, file_path)

        if should_skip(file_path, config):
            continue

        full_path = repo_path / file_path
        if not full_path.is_file():
            continue

        if full_path.stat().st_size > config.max_file_size_kb * 1024:
            continue

        try:
            content = full_path.read_bytes()
        except (OSError, PermissionError):
            continue

        text = try_decode(content)
        if text is None:
            continue

        findings.extend(secrets.scan_for_secrets(text, file_path, config))
        findings.extend(urls.scan_for_internal_references(text, file_path, config))
        findings.extend(algorithms.scan_for_sensitive_algorithms(text, file_path, config))

    return findings


def scan(
    repo_path: str | Path,
    config: Config,
    progress_callback=None,
) -> ScanReport:
    """Run a full scan on a repository."""
    repo_path = Path(repo_path)
    report = ScanReport(repo_path=str(repo_path), scan_history=config.scan_history)

    logger.info("Scanning working tree...")
    report.add_findings(scan_working_tree(repo_path, config, progress_callback))

    if config.scan_history:
        logger.info("Scanning git history...")
        report.add_findings(scan_git_history(repo_path, config, progress_callback))

    logger.info("Scanning for internal dependencies...")
    report.internal_dependencies = dependencies.find_internal_dependencies(repo_path, config)

    return report
