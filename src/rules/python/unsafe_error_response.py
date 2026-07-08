from __future__ import annotations

from domain import FindingCandidate
from parsing import FileAnalysisContext
from rules.common import exception_block_candidates, line_candidates


class PythonUnsafeErrorResponseRule:
    rule_id = "ERR-002"
    languages = {"python"}

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
