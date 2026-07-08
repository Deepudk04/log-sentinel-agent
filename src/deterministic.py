from __future__ import annotations

import re
from collections.abc import Iterable

from domain import CodeFile, Finding, FindingCandidate, Rule
from observability import get_logger
from rules.registry import analyzers_for_language
from treesitter import ParsedTree, TreeSitterService

logger = get_logger("deterministic")

LOG_CALL_RE = re.compile(
    r"\b(?:logging|logger|log|auditLogger|audit_logger|audit|LOGGER|LOG)"
    r"\s*(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*\(",
    re.IGNORECASE,
)
CONSOLE_LOG_RE = re.compile(
    r"\b(?:System\.(?:out|err)\.println|printStackTrace|traceback\.print_exc|print)\s*\(",
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
EXCEPTION_NODE_TYPES = {"except_clause", "catch_clause"}


class DeterministicAnalyzer:
    def __init__(self, rules: Iterable[Rule], tree_sitter: TreeSitterService | None = None) -> None:
        self.rules = {rule.id: rule for rule in rules}
        self.tree_sitter = tree_sitter or TreeSitterService()

    def analyze(self, files: list[CodeFile]) -> tuple[list[Finding], list[str]]:
        candidates: list[FindingCandidate] = []
        notes: list[str] = []

        for code_file in files:
            logger.debug("Analyzing file: %s", code_file.relative_path)
            context = self.tree_sitter.analyze_file(code_file)
            parsed = context.parsed_tree
            if not parsed.parser_available and parsed.error:
                logger.warning(
                    "Parser unavailable for %s; using regex fallback: %s",
                    code_file.relative_path,
                    parsed.error,
                )
                notes.append(f"{code_file.relative_path}: {parsed.error}; regex fallback used.")
            before = len(candidates)
            for analyzer in analyzers_for_language(code_file.language):
                candidates.extend(analyzer.analyze(context))
            logger.debug(
                "File analysis complete: %s candidates_added=%s",
                code_file.relative_path,
                len(candidates) - before,
            )

        findings = [self._finding_from_candidate(candidate) for candidate in candidates]
        deduped = _dedupe(findings)
        logger.info(
            "Deterministic analyzer finished: raw_candidates=%s deduped_findings=%s notes=%s",
            len(candidates),
            len(deduped),
            len(notes),
        )
        return deduped, notes

    def _finding_from_candidate(self, candidate: FindingCandidate) -> Finding:
        rule = self.rules[candidate.rule_id]
        return Finding(
            rule_id=rule.id,
            rule_title=rule.title,
            severity=rule.severity,
            category=rule.category,
            analyzer=candidate.analyzer,
            path=candidate.path,
            line=candidate.line,
            message=candidate.message,
            evidence=candidate.evidence,
            recommendation=rule.recommendation,
            confidence=candidate.confidence,
            source_refs=rule.source_refs,
        )

    def _scan_lines(self, code_file: CodeFile) -> list[Finding]:
        findings: list[Finding] = []
        for line_no, line in enumerate(code_file.lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "*")):
                continue

            if (
                LOG_CALL_RE.search(line)
                and SENSITIVE_RE.search(line)
                and not SAFE_TRANSFORM_RE.search(line)
            ):
                findings.append(
                    self._finding(
                        "LOG-003",
                        code_file,
                        line_no,
                        line,
                        "Sensitive-looking value appears in a logging call.",
                        0.82,
                    )
                )
                logger.debug("Detected LOG-003 in %s:%s", code_file.relative_path, line_no)

            if (
                LOG_CALL_RE.search(line)
                and UNTRUSTED_INPUT_RE.search(line)
                and not SANITIZER_RE.search(line)
            ):
                findings.append(
                    self._finding(
                        "LOG-004",
                        code_file,
                        line_no,
                        line,
                        "Untrusted-looking data is logged without visible sanitization.",
                        0.66,
                    )
                )
                logger.debug("Detected LOG-004 in %s:%s", code_file.relative_path, line_no)

            if DISABLE_LOGGING_RE.search(line):
                findings.append(
                    self._finding(
                        "LOG-007",
                        code_file,
                        line_no,
                        line,
                        "Code or configuration appears able to disable logging.",
                        0.86,
                    )
                )
                logger.debug("Detected LOG-007 in %s:%s", code_file.relative_path, line_no)

            if TECHNICAL_RESPONSE_RE.search(line):
                findings.append(
                    self._finding(
                        "ERR-002",
                        code_file,
                        line_no,
                        line,
                        "Technical exception details appear to be returned or rendered.",
                        0.78,
                    )
                )
                logger.debug("Detected ERR-002 in %s:%s", code_file.relative_path, line_no)

        return findings

    def _scan_exception_blocks(self, code_file: CodeFile, parsed: ParsedTree) -> list[Finding]:
        if parsed.root_node is None:
            return self._scan_exception_blocks_by_text(code_file)

        findings: list[Finding] = []
        for node in parsed.find_nodes(EXCEPTION_NODE_TYPES):
            text = parsed.node_text(node)
            start_line = parsed.start_line(node)
            findings.extend(self._analyze_exception_text(code_file, text, start_line))
        return findings

    def _scan_exception_blocks_by_text(self, code_file: CodeFile) -> list[Finding]:
        findings: list[Finding] = []
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
            block = "\n".join(lines[idx : min(idx + 14, len(lines))])
            findings.extend(self._analyze_exception_text(code_file, block, idx + 1))
        return findings

    def _analyze_exception_text(
        self,
        code_file: CodeFile,
        text: str,
        start_line: int,
    ) -> list[Finding]:
        findings: list[Finding] = []
        has_standard_log = bool(LOG_CALL_RE.search(text))
        has_console_log = bool(CONSOLE_LOG_RE.search(text))
        has_propagation = bool(PROPAGATION_RE.search(text))
        has_technical_response = bool(TECHNICAL_RESPONSE_RE.search(text))

        if not has_standard_log and not has_console_log and not has_propagation:
            findings.append(
                self._finding(
                    "ERR-003",
                    code_file,
                    start_line,
                    _shorten(text),
                    "Caught exception is not logged or propagated.",
                    0.78,
                )
            )

        if has_console_log:
            findings.append(
                self._finding(
                    "LOG-005",
                    code_file,
                    start_line,
                    _shorten(text),
                    "Exception handling uses console-style logging instead of the standard logger.",
                    0.74,
                )
            )

        if has_technical_response:
            findings.append(
                self._finding(
                    "ERR-002",
                    code_file,
                    start_line,
                    _shorten(text),
                    "Exception handler appears to expose raw technical error details.",
                    0.84,
                )
            )
            if not has_standard_log:
                findings.append(
                    self._finding(
                        "ERR-001",
                        code_file,
                        start_line,
                        _shorten(text),
                        "Exception details appear to be returned without server-side logging.",
                        0.76,
                    )
                )

        if _logs_exception_message_without_stack(text):
            findings.append(
                self._finding(
                    "ERR-001",
                    code_file,
                    start_line,
                    _shorten(text),
                    "Exception logging may omit stack context needed for investigation.",
                    0.64,
                )
            )

        return findings

    def _finding(
        self,
        rule_id: str,
        code_file: CodeFile,
        line: int,
        evidence: str,
        message: str,
        confidence: float,
    ) -> Finding:
        rule = self.rules[rule_id]
        return Finding(
            rule_id=rule.id,
            rule_title=rule.title,
            severity=rule.severity,
            category=rule.category,
            analyzer="deterministic",
            path=code_file.relative_path,
            line=line,
            message=message,
            evidence=evidence.strip(),
            recommendation=rule.recommendation,
            confidence=confidence,
            source_refs=rule.source_refs,
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


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, str]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.path, finding.line, finding.message)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
