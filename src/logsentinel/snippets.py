from __future__ import annotations

import re

from logsentinel.domain import CodeFile, Finding, Snippet
from logsentinel.observability import get_logger
from logsentinel.treesitter import TreeSitterService

logger = get_logger("snippets")

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
        logger.info(
            "Starting snippet collection: files=%s findings=%s limit=%s",
            len(files),
            len(findings),
            max_snippets,
        )
        snippets: list[Snippet] = []
        seen: set[tuple[str, int, int]] = set()
        by_path = {code_file.relative_path: code_file for code_file in files}

        for finding in findings:
            code_file = by_path.get(finding.path)
            if code_file is None:
                logger.debug("Skipping finding without matching file: %s", finding.path)
                continue
            self._add_line_window(
                snippets,
                seen,
                code_file,
                finding.line,
                f"deterministic finding {finding.rule_id}",
            )
            if len(snippets) >= max_snippets:
                logger.info("Snippet limit reached from deterministic findings: %s", len(snippets))
                return snippets

        for code_file in files:
            logger.debug("Collecting semantic hotspots from %s", code_file.relative_path)
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
                        logger.info("Snippet limit reached from Tree-sitter hotspots: %s", len(snippets))
                        return snippets
            else:
                logger.debug("Using regex hotspot fallback for %s", code_file.relative_path)
                self._add_hotword_windows(snippets, seen, code_file, max_snippets)
                if len(snippets) >= max_snippets:
                    logger.info("Snippet limit reached from regex hotspots: %s", len(snippets))
                    return snippets

        logger.info("Snippet collection finished: snippets=%s", len(snippets))
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
            logger.debug(
                "Skipping duplicate snippet: %s:%s-%s",
                snippet.path,
                snippet.start_line,
                snippet.end_line,
            )
            return
        seen.add(key)
        snippets.append(snippet)
        logger.debug(
            "Added snippet: %s:%s-%s reason=%s",
            snippet.path,
            snippet.start_line,
            snippet.end_line,
            snippet.reason,
        )


def _clip(text: str, max_chars: int = 5000) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n..."
