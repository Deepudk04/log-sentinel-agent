from __future__ import annotations

from logsentinel.domain import FindingCandidate
from logsentinel.parsing import FileAnalysisContext
from logsentinel.rules.common import exception_block_candidates, line_candidates


class JavaUnsafeErrorResponseRule:
    rule_id = "ERR-002"
    languages = {"java"}

    def analyze(self, context: FileAnalysisContext) -> list[FindingCandidate]:
        candidates = [
            *line_candidates(context.code_file),
            *exception_block_candidates(context),
        ]
        return [
            candidate
            for candidate in candidates
            if candidate.rule_id in {"ERR-001", "ERR-002"}
        ]
