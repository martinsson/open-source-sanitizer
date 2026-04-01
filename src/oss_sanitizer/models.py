"""Data models for findings and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FindingType(Enum):
    SECRET = "secret"
    INTERNAL_URL = "internal_url"
    INTERNAL_HOSTNAME = "internal_hostname"
    SENSITIVE_ALGORITHM = "sensitive_algorithm"


@dataclass
class Finding:
    """A single compliance finding."""

    finding_type: FindingType
    description: str
    file_path: str
    line_number: int
    score: float  # 0-10 severity
    snippet: str  # code snippet for context
    explanation: str  # why this was flagged
    commit_sha: str | None = None  # set when scanning history


@dataclass
class ScanReport:
    """Complete scan report."""

    repo_path: str
    scan_history: bool
    findings: list[Finding] = field(default_factory=list)
    internal_dependencies: list = field(default_factory=list)  # list[Dependency]

    @property
    def total_score(self) -> float:
        return sum(f.score for f in self.findings)

    def findings_by_type(self) -> dict[FindingType, list[Finding]]:
        grouped: dict[FindingType, list[Finding]] = {}
        for f in self.findings:
            grouped.setdefault(f.finding_type, []).append(f)
        # Sort each group by score descending
        for group in grouped.values():
            group.sort(key=lambda x: x.score, reverse=True)
        return grouped
