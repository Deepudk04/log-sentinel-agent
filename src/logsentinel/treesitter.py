from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from logsentinel.domain import CodeFile


@dataclass
class ParsedTree:
    code_file: CodeFile
    tree: Any | None
    root_node: Any | None
    source_bytes: bytes
    parser_available: bool
    error: str | None = None

    def iter_nodes(self) -> Iterable[Any]:
        if self.root_node is None:
            return
        stack = [self.root_node]
        while stack:
            node = stack.pop()
            yield node
            children = getattr(node, "children", None) or []
            stack.extend(reversed(children))

    def find_nodes(self, node_types: set[str]) -> Iterable[Any]:
        for node in self.iter_nodes():
            if getattr(node, "type", None) in node_types:
                yield node

    def node_text(self, node: Any) -> str:
        start = getattr(node, "start_byte", 0)
        end = getattr(node, "end_byte", 0)
        return self.source_bytes[start:end].decode("utf-8", errors="replace")

    @staticmethod
    def start_line(node: Any) -> int:
        point = getattr(node, "start_point", (0, 0))
        return _point_row(point) + 1

    @staticmethod
    def end_line(node: Any) -> int:
        point = getattr(node, "end_point", (0, 0))
        return _point_row(point) + 1


class TreeSitterService:
    def __init__(self) -> None:
        self._parsers: dict[str, Any] = {}
        self._import_error: str | None = None

    def parse(self, code_file: CodeFile) -> ParsedTree:
        source_bytes = code_file.text.encode("utf-8")
        parser = self._get_parser(code_file.language)
        if parser is None:
            return ParsedTree(
                code_file=code_file,
                tree=None,
                root_node=None,
                source_bytes=source_bytes,
                parser_available=False,
                error=self._import_error or f"No parser available for {code_file.language}",
            )
        try:
            tree = parser.parse(code_file.text)
        except TypeError:
            try:
                tree = parser.parse(source_bytes)
            except Exception as exc:  # pragma: no cover - depends on parser runtime
                return ParsedTree(
                    code_file=code_file,
                    tree=None,
                    root_node=None,
                    source_bytes=source_bytes,
                    parser_available=False,
                    error=f"Tree-sitter parse failed: {exc}",
                )
        except Exception as exc:  # pragma: no cover - depends on parser runtime
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

    def _get_parser(self, language: str) -> Any | None:
        if language in self._parsers:
            return self._parsers[language]
        try:
            from tree_sitter_language_pack import get_parser
        except Exception as exc:  # pragma: no cover - exercised when optional dep is absent
            self._import_error = f"tree-sitter-language-pack unavailable: {exc}"
            return None
        try:
            parser = get_parser(language)
        except Exception as exc:  # pragma: no cover - depends on parser cache/download
            self._import_error = f"Unable to load {language} parser: {exc}"
            return None
        self._parsers[language] = parser
        return parser


def _point_row(point: Any) -> int:
    if hasattr(point, "row"):
        return int(point.row)
    return int(point[0])
