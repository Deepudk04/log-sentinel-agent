from __future__ import annotations

from typing import Protocol

from logsentinel.domain import FindingCandidate
from logsentinel.parsing import FileAnalysisContext


class RuleAnalyzer(Protocol):
    rule_id: str
    languages: set[str]

    def analyze(self, context: FileAnalysisContext) -> list[FindingCandidate]:
        ...
