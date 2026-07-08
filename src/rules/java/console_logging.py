from __future__ import annotations

from domain import FindingCandidate
from parsing import FileAnalysisContext
from rules.common import console_logging_candidates, exception_block_candidates


class JavaConsoleLoggingRule:
    rule_id = "LOG-005"
    languages = {"java"}

    def analyze(self, context: FileAnalysisContext) -> list[FindingCandidate]:
        return [
            candidate
            for candidate in [
                *console_logging_candidates(context),
                *exception_block_candidates(context),
            ]
            if candidate.rule_id == "LOG-005"
        ]
