"""Scrubber: deterministic token replacement for a category of findings."""

from __future__ import annotations

from .models import Finding, FindingType


class Scrubber:
    """Maps values from a set of finding types to stable replacement tokens.

    Register findings once; call scrub() on any number of texts — the same
    original value always produces the same token, across files and calls.
    """

    def __init__(self, token_prefix: str, finding_types: frozenset[FindingType]):
        self._token_prefix = token_prefix
        self._finding_types = finding_types
        self._replacements: dict[str, str] = {}
        self._counter = 0

    def register(self, findings: list[Finding]) -> None:
        """Learn which values to replace from a list of findings."""
        for f in findings:
            if f.finding_type in self._finding_types and f.match_value and f.match_value not in self._replacements:
                self._counter += 1
                self._replacements[f.match_value] = f"{self._token_prefix}_{self._counter}"

    def scrub(self, text: str) -> str:
        """Replace all registered values with their tokens."""
        for original, token in self._replacements.items():
            text = text.replace(original, token)
        return text

    @property
    def replacements(self) -> dict[str, str]:
        """Return {original: token} mapping."""
        return dict(self._replacements)
