from __future__ import annotations

from logsentinel.domain import FindingCandidate
from logsentinel.parsing import FileAnalysisContext
from logsentinel.rules.common import exception_block_candidates


class JavaSwallowedExceptionRule:
    rule_id = "ERR-003"
    languages = {"java"}

    def analyze(self, context: FileAnalysisContext) -> list[FindingCandidate]:
        return [
            candidate
            for candidate in exception_block_candidates(context)
            if candidate.rule_id in {"ERR-001", "ERR-003"}
        ]
