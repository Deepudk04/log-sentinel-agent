from __future__ import annotations

from config import Settings
from domain import CodeFile, Finding, FindingCandidate, Rule, Snippet
from observability import get_logger
from semantic.redactor import SecretRedactor

logger = get_logger("semantic.validator")


class SemanticFindingValidator:
    def __init__(
        self,
        rules: list[Rule],
        files: list[CodeFile],
        snippets: list[Snippet],
        settings: Settings,
        deterministic_findings: list[Finding] | None = None,
    ) -> None:
        self.rules = {rule.id: rule for rule in rules}
        self.files = {file.relative_path: file for file in files}
        self.snippets = snippets
        self.settings = settings
        self.deterministic_keys = {
            (finding.rule_id, finding.path, finding.line)
            for finding in deterministic_findings or []
            if finding.analyzer == "deterministic"
        }

    def validate(self, candidates: list[FindingCandidate]) -> tuple[list[Finding], list[str]]:
        findings: list[Finding] = []
        notes: list[str] = []
        for candidate in candidates:
            accepted, note = self._validate_one(candidate)
            if note:
                notes.append(note)
            if accepted is not None:
                findings.append(accepted)
        return findings, notes

    def _validate_one(self, candidate: FindingCandidate) -> tuple[Finding | None, str | None]:
        rule = self.rules.get(candidate.rule_id)
        if rule is None:
            return None, f"Semantic finding rejected: unknown rule_id {candidate.rule_id}"
        code_file = self.files.get(candidate.path)
        if code_file is None:
            return None, f"Semantic finding rejected: path was not scanned: {candidate.path}"
        snippet = _snippet_for_candidate(self.snippets, candidate)
        if snippet is None:
            return (
                None,
                f"Semantic finding rejected: path was not included in snippets: {candidate.path}",
            )
        if candidate.line < 1 or candidate.line > len(code_file.lines):
            return (
                None,
                "Semantic finding rejected: line outside file range: "
                f"{candidate.path}:{candidate.line}",
            )
        if not (snippet.start_line <= candidate.line <= snippet.end_line):
            return (
                None,
                "Semantic finding rejected: line outside snippet range: "
                f"{candidate.path}:{candidate.line}",
            )
        if rule.severity in {"critical", "high", "medium"} and not candidate.evidence.strip():
            return None, f"Semantic finding rejected: missing evidence for {candidate.rule_id}"
        if (
            candidate.evidence
            and candidate.evidence not in snippet.text
            and candidate.evidence not in code_file.text
        ):
            return (
                None,
                f"Semantic finding rejected: evidence not found in source: {candidate.path}",
            )
        confidence = min(max(candidate.confidence, 0.0), 1.0)
        if confidence < self.settings.semantic_min_confidence:
            return (
                None,
                f"Semantic finding rejected: confidence below threshold for {candidate.rule_id}",
            )
        if (candidate.rule_id, candidate.path, candidate.line) in self.deterministic_keys:
            return (
                None,
                "Semantic finding rejected: duplicates deterministic finding: "
                f"{candidate.path}:{candidate.line}",
            )

        redactor = SecretRedactor()
        recommendation = candidate.recommendation or rule.recommendation
        return (
            Finding(
                rule_id=rule.id,
                rule_title=rule.title,
                severity=rule.severity,
                category=rule.category,
                analyzer="semantic",
                path=candidate.path,
                line=candidate.line,
                message=candidate.message or "Semantic rule matched.",
                evidence=redactor.redact(candidate.evidence),
                recommendation=recommendation,
                confidence=confidence,
                source_refs=rule.source_refs,
            ),
            None,
        )


def _snippet_for_candidate(snippets: list[Snippet], candidate: FindingCandidate) -> Snippet | None:
    for snippet in snippets:
        if (
            snippet.path == candidate.path
            and snippet.start_line <= candidate.line <= snippet.end_line
        ):
            return snippet
    return None
