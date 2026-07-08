from __future__ import annotations

import re

from logsentinel.domain import CodeFile, Finding, Snippet
from logsentinel.treesitter import TreeSitterService

HOTWORD_RE = re.compile(
    r"(login|auth|authorize|permission|role|session|validate|validator|exception|error|"
    r"catch|except|logger|logging|audit|password|token|secret|request|header|payload|"
    r"upload|deserialize|export|admin)",
    re.IGNORECASE,
)
SNIPPET_NODE_TYPES = {
    "function_definition",
    "class_definition",
    "method_declaration",
    "constructor_declaration",
    "catch_clause",
    "except_clause",
}


class SnippetCollector:
    def __init__(self, tree_sitter: TreeSitterService | None = None) -> None:
        self.tree_sitter = tree_sitter or TreeSitterService()

    def collect(
        self,
        files: list[CodeFile],
        findings: list[Finding],
        max_snippets: int,
    ) -> list[Snippet]:
        snippets: list[Snippet] = []
        seen: set[tuple[str, int, int]] = set()
        by_path = {code_file.relative_path: code_file for code_file in files}

        for finding in findings:
            code_file = by_path.get(finding.path)
            if code_file is None:
                continue
            self._add_line_window(
                snippets,
                seen,
                code_file,
                finding.line,
                f"deterministic finding {finding.rule_id}",
            )
            if len(snippets) >= max_snippets:
                return snippets

        for code_file in files:
            parsed = self.tree_sitter.parse(code_file)
            if parsed.root_node is not None:
                for node in parsed.find_nodes(SNIPPET_NODE_TYPES):
                    text = parsed.node_text(node)
                    if not HOTWORD_RE.search(text):
                        continue
                    start_line = parsed.start_line(node)
                    end_line = parsed.end_line(node)
                    self._add_snippet(
                        snippets,
                        seen,
                        Snippet(
                            path=code_file.relative_path,
                            language=code_file.language,
                            start_line=start_line,
                            end_line=end_line,
                            text=_clip(text),
                            reason="semantic hotspot",
                        ),
                    )
                    if len(snippets) >= max_snippets:
                        return snippets
            else:
                self._add_hotword_windows(snippets, seen, code_file, max_snippets)
                if len(snippets) >= max_snippets:
                    return snippets

        return snippets

    def _add_hotword_windows(
        self,
        snippets: list[Snippet],
        seen: set[tuple[str, int, int]],
        code_file: CodeFile,
        max_snippets: int,
    ) -> None:
        for line_no, line in enumerate(code_file.lines, start=1):
            if not HOTWORD_RE.search(line):
                continue
            self._add_line_window(snippets, seen, code_file, line_no, "semantic hotspot")
            if len(snippets) >= max_snippets:
                return

    def _add_line_window(
        self,
        snippets: list[Snippet],
        seen: set[tuple[str, int, int]],
        code_file: CodeFile,
        line_no: int,
        reason: str,
        radius: int = 8,
    ) -> None:
        lines = code_file.lines
        start = max(1, line_no - radius)
        end = min(len(lines), line_no + radius)
        text = "\n".join(lines[start - 1 : end])
        self._add_snippet(
            snippets,
            seen,
            Snippet(
                path=code_file.relative_path,
                language=code_file.language,
                start_line=start,
                end_line=end,
                text=_clip(text),
                reason=reason,
            ),
        )

    @staticmethod
    def _add_snippet(
        snippets: list[Snippet],
        seen: set[tuple[str, int, int]],
        snippet: Snippet,
    ) -> None:
        key = (snippet.path, snippet.start_line, snippet.end_line)
        if key in seen:
            return
        seen.add(key)
        snippets.append(snippet)


def _clip(text: str, max_chars: int = 5000) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n..."
