from __future__ import annotations

import re

from logsentinel.domain import CodeFile
from logsentinel.parsing.models import CodeCall, CodeSymbol, ParsedBlock

PY_FUNCTION_RE = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
PY_CLASS_RE = re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b")
JAVA_CLASS_RE = re.compile(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\b")
JAVA_METHOD_RE = re.compile(
    r"^\s*(?:public|private|protected)?\s*(?:static\s+)?(?:[\w<>\[\]]+\s+)+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{?"
)
IMPORT_RE = re.compile(r"^\s*(?:import\s+[\w.*,\s]+|from\s+[\w.]+\s+import\s+.+)")
LOGGER_CALL_RE = re.compile(
    r"\b(?:logging|logger|log|auditLogger|audit_logger|audit|LOGGER|LOG)"
    r"\s*(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*\(",
    re.IGNORECASE,
)
CONSOLE_CALL_RE = re.compile(
    r"\b(?:System\.(?:out|err)\.println|printStackTrace|traceback\.print_exc|print)\s*\(",
    re.IGNORECASE,
)
API_HANDLER_RE = re.compile(
    r"(@(?:app\.)?(?:get|post|put|delete|patch)\b|@(?:Get|Post|Put|Delete|Patch)Mapping\b|"
    r"@RequestMapping\b|Controller\b|ResponseEntity\b)",
    re.IGNORECASE,
)
GLOBAL_HANDLER_RE = re.compile(
    r"(@app\.exception_handler\b|@ControllerAdvice\b|@ExceptionHandler\b|"
    r"set_exception_handler\b)",
    re.IGNORECASE,
)


def extract_symbols(code_file: CodeFile) -> list[CodeSymbol]:
    symbols: list[CodeSymbol] = []
    lines = code_file.lines
    for idx, line in enumerate(lines, start=1):
        match = PY_CLASS_RE.search(line)
        if match:
            symbols.append(CodeSymbol(match.group(1), "class", idx, _block_end(lines, idx)))
            continue
        match = PY_FUNCTION_RE.search(line)
        if match:
            kind = "method" if _looks_indented(line) else "function"
            symbols.append(CodeSymbol(match.group(1), kind, idx, _block_end(lines, idx)))
            continue
        match = JAVA_CLASS_RE.search(line)
        if match:
            symbols.append(CodeSymbol(match.group(1), "class", idx, _brace_block_end(lines, idx)))
            continue
        match = JAVA_METHOD_RE.search(line)
        if match and not line.strip().startswith(("if", "for", "while", "switch", "catch")):
            symbols.append(CodeSymbol(match.group(1), "method", idx, _brace_block_end(lines, idx)))
    return symbols


def extract_imports(code_file: CodeFile) -> list[str]:
    return [line.strip() for line in code_file.lines if IMPORT_RE.search(line)]


def extract_calls(
    code_file: CodeFile,
    symbols: list[CodeSymbol],
) -> tuple[list[CodeCall], list[CodeCall]]:
    logger_calls: list[CodeCall] = []
    console_calls: list[CodeCall] = []
    for line_no, line in enumerate(code_file.lines, start=1):
        symbol = _symbol_for_line(symbols, line_no)
        if LOGGER_CALL_RE.search(line):
            logger_calls.append(CodeCall("logger", line_no, line.strip(), symbol))
        if CONSOLE_CALL_RE.search(line):
            console_calls.append(CodeCall("console", line_no, line.strip(), symbol))
    return logger_calls, console_calls


def extract_exception_blocks(code_file: CodeFile, symbols: list[CodeSymbol]) -> list[ParsedBlock]:
    blocks: list[ParsedBlock] = []
    lines = code_file.lines
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not (
            stripped.startswith("except ")
            or stripped.startswith("except:")
            or stripped.startswith("catch ")
            or stripped.startswith("} catch")
        ):
            continue
        start_line = idx + 1
        end_line = min(start_line + 13, len(lines))
        text = "\n".join(lines[idx:end_line])
        kind = "catch" if "catch" in stripped else "exception"
        blocks.append(
            ParsedBlock(kind, start_line, end_line, text, _symbol_for_line(symbols, start_line))
        )
    return blocks


def extract_api_contexts(
    code_file: CodeFile,
    symbols: list[CodeSymbol],
) -> tuple[list[ParsedBlock], list[ParsedBlock]]:
    handlers: list[ParsedBlock] = []
    global_handlers: list[ParsedBlock] = []
    lines = code_file.lines
    for idx, line in enumerate(lines):
        if not API_HANDLER_RE.search(line) and not GLOBAL_HANDLER_RE.search(line):
            continue
        start_line = idx + 1
        end_line = min(start_line + 12, len(lines))
        text = "\n".join(lines[idx:end_line])
        symbol = _symbol_for_line(symbols, start_line)
        if GLOBAL_HANDLER_RE.search(line):
            global_handlers.append(
                ParsedBlock("global_exception_handler", start_line, end_line, text, symbol)
            )
        else:
            handlers.append(ParsedBlock("api_handler", start_line, end_line, text, symbol))
    return handlers, global_handlers


def _symbol_for_line(symbols: list[CodeSymbol], line_no: int) -> str | None:
    containing = [
        symbol for symbol in symbols if symbol.start_line <= line_no <= symbol.end_line
    ]
    if not containing:
        return None
    return max(containing, key=lambda item: item.start_line).name


def _looks_indented(line: str) -> bool:
    return bool(line) and line[0].isspace()


def _block_end(lines: list[str], start_line: int) -> int:
    if start_line > len(lines):
        return start_line
    start_text = lines[start_line - 1]
    indent = len(start_text) - len(start_text.lstrip())
    end = start_line
    for idx in range(start_line, len(lines)):
        line = lines[idx]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            end = idx + 1
            continue
        current_indent = len(line) - len(line.lstrip())
        if current_indent <= indent:
            break
        end = idx + 1
    return end


def _brace_block_end(lines: list[str], start_line: int) -> int:
    depth = 0
    seen_open = False
    for idx in range(start_line - 1, len(lines)):
        line = lines[idx]
        depth += line.count("{")
        if "{" in line:
            seen_open = True
        depth -= line.count("}")
        if seen_open and depth <= 0:
            return idx + 1
    return min(start_line + 20, len(lines))
