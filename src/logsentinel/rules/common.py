from __future__ import annotations

import re

from logsentinel.domain import CodeFile, FindingCandidate
from logsentinel.parsing import FileAnalysisContext, ParsedBlock

LOG_CALL_RE = re.compile(
    r"\b(?:logging|logger|log|auditLogger|audit_logger|audit|LOGGER|LOG)"
    r"\s*(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*\(",
    re.IGNORECASE,
)
SENSITIVE_RE = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|session[_-]?id|"
    r"session|ssn|social[_-]?security|credit[_-]?card|cardholder|card_number|cvv|"
    r"connection[_-]?string|private[_-]?key)",
    re.IGNORECASE,
)
SAFE_TRANSFORM_RE = re.compile(
    r"(mask|masked|redact|redacted|hash|hashed|tokenize|scrub|sanitize|pseudonym|"
    r"anonym|obfuscate)",
    re.IGNORECASE,
)
UNTRUSTED_INPUT_RE = re.compile(
    r"(request|headers?|params?|query|payload|body|input|user_agent|cookie|filename|path|"
    r"external|client|form|args)",
    re.IGNORECASE,
)
SANITIZER_RE = re.compile(
    r"(sanitize|escape|encode|normalize|replace|strip|validate|structured|extra=|MDC\.put)",
    re.IGNORECASE,
)
DISABLE_LOGGING_RE = re.compile(
    r"(logging\.disable\s*\(|\.disabled\s*=\s*True\b|Level\.OFF\b|level\s*=\s*[\"']OFF[\"'])",
    re.IGNORECASE,
)
CONSOLE_LOG_RE = re.compile(
    r"\b(?:System\.(?:out|err)\.println|printStackTrace|traceback\.print_exc|print)\s*\(",
    re.IGNORECASE,
)
TECHNICAL_RESPONSE_RE = re.compile(
    r"(return\s+str\s*\(\s*\w+\s*\)|detail\s*=\s*str\s*\(|"
    r"jsonify\s*\([^;\n]*(?:str\s*\(|traceback|format_exc|\.args)|"
    r"ResponseEntity[^;\n]*body\s*\([^;\n]*\.getMessage\s*\(|"
    r"sendError\s*\([^;\n]*\.getMessage\s*\(|"
    r"return\s+[^;\n]*\.getMessage\s*\(|"
    r"traceback\.format_exc\s*\(|stackTrace)",
    re.IGNORECASE,
)
PROPAGATION_RE = re.compile(r"\b(raise|throw)\b")


def line_candidates(code_file: CodeFile) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []
    for line_no, line in enumerate(code_file.lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*")):
            continue
        if (
            LOG_CALL_RE.search(line)
            and SENSITIVE_RE.search(line)
            and not SAFE_TRANSFORM_RE.search(line)
        ):
            candidates.append(
                _candidate(
                    "LOG-003",
                    code_file,
                    line_no,
                    line,
                    "Sensitive-looking value appears in a logging call.",
                    0.82,
                    ["log_call", "sensitive_token"],
                )
            )
        if (
            LOG_CALL_RE.search(line)
            and UNTRUSTED_INPUT_RE.search(line)
            and not SANITIZER_RE.search(line)
        ):
            candidates.append(
                _candidate(
                    "LOG-004",
                    code_file,
                    line_no,
                    line,
                    "Untrusted-looking data is logged without visible sanitization.",
                    0.66,
                    ["log_call", "untrusted_input", "missing_sanitizer"],
                )
            )
        if DISABLE_LOGGING_RE.search(line):
            candidates.append(
                _candidate(
                    "LOG-007",
                    code_file,
                    line_no,
                    line,
                    "Code or configuration appears able to disable logging.",
                    0.86,
                    ["logging_disable_signal"],
                )
            )
        if TECHNICAL_RESPONSE_RE.search(line):
            candidates.append(
                _candidate(
                    "ERR-002",
                    code_file,
                    line_no,
                    line,
                    "Technical exception details appear to be returned or rendered.",
                    0.78,
                    ["technical_error_response"],
                )
            )
    return candidates


def exception_block_candidates(context: FileAnalysisContext) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []
    for block in context.exception_blocks:
        candidates.extend(_analyze_exception_block(context.code_file, block))
    return candidates


def console_logging_candidates(context: FileAnalysisContext) -> list[FindingCandidate]:
    return [
        _candidate(
            "LOG-005",
            context.code_file,
            call.line,
            call.text,
            "Exception handling uses console-style logging instead of the standard logger.",
            0.74,
            ["console_logging"],
            call.symbol,
        )
        for call in context.console_calls
    ]


def _analyze_exception_block(code_file: CodeFile, block: ParsedBlock) -> list[FindingCandidate]:
    text = block.text
    has_standard_log = bool(LOG_CALL_RE.search(text))
    has_console_log = bool(CONSOLE_LOG_RE.search(text))
    has_propagation = bool(PROPAGATION_RE.search(text))
    has_technical_response = bool(TECHNICAL_RESPONSE_RE.search(text))
    candidates: list[FindingCandidate] = []

    if not has_standard_log and not has_console_log and not has_propagation:
        candidates.append(
            _candidate(
                "ERR-003",
                code_file,
                block.start_line,
                _shorten(text),
                "Caught exception is not logged or propagated.",
                0.78,
                ["catch_block", "missing_log_or_propagation"],
                block.symbol,
            )
        )

    if has_console_log:
        candidates.append(
            _candidate(
                "LOG-005",
                code_file,
                block.start_line,
                _shorten(text),
                "Exception handling uses console-style logging instead of the standard logger.",
                0.74,
                ["catch_block", "console_logging"],
                block.symbol,
            )
        )

    if has_technical_response:
        candidates.append(
            _candidate(
                "ERR-002",
                code_file,
                block.start_line,
                _shorten(text),
                "Exception handler appears to expose raw technical error details.",
                0.84,
                ["catch_block", "technical_error_response"],
                block.symbol,
            )
        )
        if not has_standard_log:
            candidates.append(
                _candidate(
                    "ERR-001",
                    code_file,
                    block.start_line,
                    _shorten(text),
                    "Exception details appear to be returned without server-side logging.",
                    0.76,
                    ["catch_block", "technical_error_response", "missing_server_log"],
                    block.symbol,
                )
            )

    if _logs_exception_message_without_stack(text):
        candidates.append(
            _candidate(
                "ERR-001",
                code_file,
                block.start_line,
                _shorten(text),
                "Exception logging may omit stack context needed for investigation.",
                0.64,
                ["exception_message_without_stack"],
                block.symbol,
            )
        )

    return candidates


def _candidate(
    rule_id: str,
    code_file: CodeFile,
    line: int,
    evidence: str,
    message: str,
    confidence: float,
    signals: list[str],
    symbol: str | None = None,
) -> FindingCandidate:
    return FindingCandidate(
        rule_id=rule_id,
        path=code_file.relative_path,
        line=line,
        message=message,
        evidence=evidence.strip(),
        analyzer="deterministic",
        confidence=confidence,
        language=code_file.language,
        symbol=symbol,
        deterministic_signals=signals,
    )


def _logs_exception_message_without_stack(text: str) -> bool:
    lower = text.lower()
    if "logger.exception" in lower or "exc_info=true" in lower:
        return False
    if re.search(r"\b(?:logger|log|logging)\s*\.\s*(?:error|warning|warn|critical)\s*\(", text):
        if re.search(r"(str\s*\(\s*\w+\s*\)|\.getMessage\s*\(\)|\bargs\b)", text):
            return True
    return False


def _shorten(text: str, max_lines: int = 12) -> str:
    lines = [line.rstrip() for line in text.strip().splitlines()]
    if len(lines) <= max_lines:
        return "\n".join(lines)
    return "\n".join(lines[:max_lines] + ["..."])
