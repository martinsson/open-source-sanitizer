"""Data models for findings and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanners.pom.model import PomDependency


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
    internal_dependencies: list[PomDependency] = field(default_factory=list)
    _seen: set[tuple] = field(default_factory=set, repr=False)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding, ignoring duplicates (same type/file/line/description)."""
        key = (finding.finding_type, finding.file_path, finding.line_number, finding.description)
        if key not in self._seen:
            self._seen.add(key)
            self.findings.append(finding)

    def add_findings(self, findings: list[Finding]) -> None:
        for f in findings:
            self.add_finding(f)

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
