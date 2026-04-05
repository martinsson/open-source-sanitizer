"""PomDependency dataclass."""

from __future__ import annotations

from dataclasses import dataclass

_NON_SHIPPING_SCOPES = frozenset({"test", "provided", "system"})


@dataclass
class PomDependency:
    group_id: str
    artifact_id: str
    version: str | None
    scope: str | None
    pom_path: str
    line_number: int

    @property
    def is_shipping(self) -> bool:
        """A dependency ships in the binary unless its scope is test/provided/system."""
        return (self.scope or "compile") not in _NON_SHIPPING_SCOPES
