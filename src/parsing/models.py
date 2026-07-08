from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

from domain import CodeFile


@dataclass(frozen=True)
class CodeSymbol:
    name: str
    kind: Literal["class", "function", "method", "constructor", "unknown"]
    start_line: int
    end_line: int


@dataclass(frozen=True)
class ParsedBlock:
    kind: Literal["exception", "catch", "api_handler", "global_exception_handler"]
    start_line: int
    end_line: int
    text: str
    symbol: str | None = None


@dataclass(frozen=True)
class CodeCall:
    kind: Literal["logger", "console"]
    line: int
    text: str
    symbol: str | None = None


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


@dataclass(frozen=True)
class FileAnalysisContext:
    code_file: CodeFile
    parsed_tree: ParsedTree
    symbols: list[CodeSymbol] = field(default_factory=list)
    exception_blocks: list[ParsedBlock] = field(default_factory=list)
    logger_calls: list[CodeCall] = field(default_factory=list)
    console_calls: list[CodeCall] = field(default_factory=list)
    api_handlers: list[ParsedBlock] = field(default_factory=list)
    global_exception_handlers: list[ParsedBlock] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)


def _point_row(point: Any) -> int:
    if hasattr(point, "row"):
        return int(point.row)
    return int(point[0])
