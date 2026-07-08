from __future__ import annotations

from typing import Any

from domain import CodeFile
from observability import get_logger
from parsing import fallback
from parsing.models import FileAnalysisContext, ParsedBlock, ParsedTree

logger = get_logger("treesitter")

SYMBOL_NODE_TYPES = {
    "class_definition",
    "function_definition",
    "method_declaration",
    "constructor_declaration",
    "class_declaration",
}
EXCEPTION_NODE_TYPES = {"except_clause", "catch_clause"}


class TreeSitterService:
    def __init__(self) -> None:
        self._parsers: dict[str, Any] = {}
        self._import_error: str | None = None

    def parse(self, code_file: CodeFile) -> ParsedTree:
        source_bytes = code_file.text.encode("utf-8")
        parser = self._get_parser(code_file.language)
        if parser is None:
            logger.warning(
                "No Tree-sitter parser available for %s file %s: %s",
                code_file.language,
                code_file.relative_path,
                self._import_error or "unknown parser error",
            )
            return ParsedTree(
                code_file=code_file,
                tree=None,
                root_node=None,
                source_bytes=source_bytes,
                parser_available=False,
                error=self._import_error or f"No parser available for {code_file.language}",
            )
        try:
            logger.debug("Parsing %s with Tree-sitter as bytes", code_file.relative_path)
            tree = parser.parse(source_bytes)
        except TypeError:
            logger.debug(
                "Bytes parse was not accepted for %s; retrying as text",
                code_file.relative_path,
            )
            try:
                tree = parser.parse(code_file.text)
            except Exception as exc:  # pragma: no cover - depends on parser runtime
                logger.warning("Tree-sitter parse failed for %s: %s", code_file.relative_path, exc)
                return ParsedTree(
                    code_file=code_file,
                    tree=None,
                    root_node=None,
                    source_bytes=source_bytes,
                    parser_available=False,
                    error=f"Tree-sitter parse failed: {exc}",
                )
        except Exception as exc:  # pragma: no cover - depends on parser runtime
            logger.warning("Tree-sitter parse failed for %s: %s", code_file.relative_path, exc)
            return ParsedTree(
                code_file=code_file,
                tree=None,
                root_node=None,
                source_bytes=source_bytes,
                parser_available=False,
                error=f"Tree-sitter parse failed: {exc}",
            )
        return ParsedTree(
            code_file=code_file,
            tree=tree,
            root_node=tree.root_node,
            source_bytes=source_bytes,
            parser_available=True,
        )

    def analyze_file(self, code_file: CodeFile) -> FileAnalysisContext:
        parsed = self.parse(code_file)
        symbols = fallback.extract_symbols(code_file)
        exception_blocks = self._tree_exception_blocks(parsed) or fallback.extract_exception_blocks(
            code_file, symbols
        )
        logger_calls, console_calls = fallback.extract_calls(code_file, symbols)
        api_handlers, global_exception_handlers = fallback.extract_api_contexts(code_file, symbols)
        imports = fallback.extract_imports(code_file)
        return FileAnalysisContext(
            code_file=code_file,
            parsed_tree=parsed,
            symbols=symbols,
            exception_blocks=exception_blocks,
            logger_calls=logger_calls,
            console_calls=console_calls,
            api_handlers=api_handlers,
            global_exception_handlers=global_exception_handlers,
            imports=imports,
        )

    def _tree_exception_blocks(self, parsed: ParsedTree) -> list[ParsedBlock]:
        if parsed.root_node is None:
            return []
        blocks: list[ParsedBlock] = []
        for node in parsed.find_nodes(EXCEPTION_NODE_TYPES):
            text = parsed.node_text(node)
            start_line = parsed.start_line(node)
            end_line = parsed.end_line(node)
            kind = "catch" if getattr(node, "type", "") == "catch_clause" else "exception"
            blocks.append(ParsedBlock(kind, start_line, end_line, text))
        return blocks

    def _get_parser(self, language: str) -> Any | None:
        if language in self._parsers:
            logger.debug("Using cached Tree-sitter parser for %s", language)
            return self._parsers[language]
        try:
            from tree_sitter_language_pack import get_parser
        except Exception as exc:  # pragma: no cover - exercised when optional dep is absent
            self._import_error = f"tree-sitter-language-pack unavailable: {exc}"
            logger.warning("%s", self._import_error)
            return None
        try:
            logger.debug("Loading Tree-sitter parser for %s", language)
            parser = get_parser(language)
        except Exception as exc:  # pragma: no cover - depends on parser cache/download
            self._import_error = f"Unable to load {language} parser: {exc}"
            logger.warning("%s", self._import_error)
            return None
        self._parsers[language] = parser
        logger.info("Loaded Tree-sitter parser for %s", language)
        return parser
