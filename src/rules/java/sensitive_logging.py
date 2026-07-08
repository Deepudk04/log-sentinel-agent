from __future__ import annotations

from domain import FindingCandidate
from parsing import FileAnalysisContext
from rules.common import line_candidates


class JavaSensitiveLoggingRule:
    rule_id = "LOG-003"
    languages = {"java"}

    def analyze(self, context: FileAnalysisContext) -> list[FindingCandidate]:
        return [
            candidate
            for candidate in line_candidates(context.code_file)
            if candidate.rule_id in {"LOG-003", "LOG-004", "LOG-007"}
        ]
