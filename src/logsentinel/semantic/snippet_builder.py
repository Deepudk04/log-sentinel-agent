from __future__ import annotations

import hashlib
from dataclasses import replace

from logsentinel.domain import FindingCandidate, Snippet
from logsentinel.parsing import FileAnalysisContext
from logsentinel.semantic.redactor import SecretRedactor


class SnippetBuilder:
    def __init__(
        self,
        max_lines_around_target: int = 8,
        max_chars: int = 5000,
        max_snippets_per_file: int = 20,
        redact_before_llm: bool = True,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self.max_lines_around_target = max_lines_around_target
        self.max_chars = max_chars
        self.max_snippets_per_file = max_snippets_per_file
        self.redact_before_llm = redact_before_llm
        self.redactor = redactor or SecretRedactor()

    def from_candidates(
        self,
        context: FileAnalysisContext,
        candidates: list[FindingCandidate],
    ) -> list[Snippet]:
        snippets: list[Snippet] = []
        seen: set[tuple[int, int]] = set()
        for candidate in candidates:
            if len(snippets) >= self.max_snippets_per_file:
                break
            start = max(1, candidate.line - self.max_lines_around_target)
            end = min(len(context.code_file.lines), candidate.line + self.max_lines_around_target)
            key = (start, end)
            if key in seen:
                continue
            seen.add(key)
            text = "\n".join(context.code_file.lines[start - 1 : end])
            if self.redact_before_llm:
                text = self.redactor.redact(text)
            snippets.append(
                Snippet(
                    path=context.code_file.relative_path,
                    language=context.code_file.language,
                    start_line=start,
                    end_line=end,
                    text=_clip(text, self.max_chars),
                    reason=f"candidate rules: {', '.join(sorted({candidate.rule_id}))}",
                    snippet_id=_snippet_id(context.code_file.relative_path, start, end, text),
                    symbol=candidate.symbol,
                    candidate_rule_ids=[candidate.rule_id],
                    deterministic_signals=candidate.deterministic_signals,
                )
            )
        return snippets

    def redact_existing(self, snippets: list[Snippet]) -> list[Snippet]:
        if not self.redact_before_llm:
            return snippets
        return [
            replace(
                snippet,
                text=self.redactor.redact(snippet.text),
                snippet_id=snippet.snippet_id
                or _snippet_id(snippet.path, snippet.start_line, snippet.end_line, snippet.text),
            )
            for snippet in snippets
        ]


def _snippet_id(path: str, start_line: int, end_line: int, text: str) -> str:
    raw = f"{path}:{start_line}:{end_line}:{hashlib.sha256(text.encode()).hexdigest()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _clip(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n..."
