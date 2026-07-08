from datetime import UTC, datetime
from pathlib import Path

from logsentinel.domain import CodeFile, Finding, FindingCandidate, ScanResult
from logsentinel.parsing.treesitter_service import TreeSitterService
from logsentinel.reporting import render_markdown
from logsentinel.rule_catalog import load_rules
from logsentinel.semantic.redactor import SecretRedactor
from logsentinel.semantic.snippet_builder import SnippetBuilder


class _NoParserService(TreeSitterService):
    def _get_parser(self, language: str):
        self._import_error = f"No parser for {language}"
        return None


def test_redactor_masks_common_secret_shapes():
    text = (
        "password='super-secret'\n"
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n"
        "url = 'postgres://user:pass@example.com/db'\n"
    )

    redacted = SecretRedactor().redact(text)

    assert "super-secret" not in redacted
    assert "abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "postgres://user:pass@example.com/db" not in redacted
    assert "[REDACTED_SECRET]" in redacted
    assert "[REDACTED_TOKEN]" in redacted
    assert "[REDACTED_CONNECTION_STRING]" in redacted


def test_snippet_builder_redacts_and_adds_metadata():
    code_file = CodeFile(
        path=Path("app.py"),
        relative_path="app.py",
        language="python",
        text="def login():\n    password='super-secret'\n    logger.info(password)\n",
    )
    context = _NoParserService().analyze_file(code_file)
    candidate = FindingCandidate(
        rule_id="LOG-003",
        path="app.py",
        line=2,
        message="Sensitive-looking value appears in a logging call.",
        evidence="password='super-secret'",
        analyzer="deterministic",
        confidence=0.8,
        language="python",
        symbol="login",
        deterministic_signals=["sensitive_token"],
    )

    snippets = SnippetBuilder().from_candidates(context, [candidate])

    assert snippets[0].snippet_id
    assert snippets[0].symbol == "login"
    assert snippets[0].candidate_rule_ids == ["LOG-003"]
    assert "super-secret" not in snippets[0].text


def test_markdown_report_redacts_finding_evidence():
    rule = next(rule for rule in load_rules() if rule.id == "LOG-003")
    result = ScanResult(
        repository="repo",
        generated_at=datetime(2026, 7, 8, tzinfo=UTC),
        scanned_files=1,
        skipped=[],
        findings=[
            Finding(
                rule_id=rule.id,
                rule_title=rule.title,
                severity=rule.severity,
                category=rule.category,
                analyzer="deterministic",
                path="app.py",
                line=1,
                message="Sensitive value.",
                evidence="password='super-secret'",
                recommendation=rule.recommendation,
                confidence=0.9,
                source_refs=rule.source_refs,
            )
        ],
        snippets_sent=0,
        rules=[rule],
        notes=[],
        markdown_report="",
    )

    markdown = render_markdown(result)

    assert "super-secret" not in markdown
    assert "[REDACTED_SECRET]" in markdown
