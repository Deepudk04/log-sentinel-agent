from __future__ import annotations

from typing import Protocol

from domain import FindingCandidate
from parsing import FileAnalysisContext


class RuleAnalyzer(Protocol):
    rule_id: str
    languages: set[str]

    def analyze(self, context: FileAnalysisContext) -> list[FindingCandidate]:
        ...
