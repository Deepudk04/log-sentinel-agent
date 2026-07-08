from pathlib import Path

from config import Settings
from domain import CodeFile, FindingCandidate, Snippet
from rule_catalog import load_rules
from semantic.response_parser import SemanticResponseParser
from semantic.validator import SemanticFindingValidator


def _settings() -> Settings:
    return Settings(
        gemini_api_key=None,
        gemini_model="gemini-3.5-flash",
        output_dir=Path("reports"),
        max_file_bytes=1024,
        max_files=100,
        max_snippets=40,
        languages_include=("python", "java"),
        languages_exclude=(),
        ignore_patterns=(),
        max_snippets_per_file=20,
        semantic_enabled=True,
        semantic_provider="gemini",
        semantic_min_confidence=0.7,
        redact_before_llm=True,
        report_formats=("markdown",),
        fail_on_severity="high",
    )


def test_semantic_response_parser_rejects_invalid_json():
    parsed = SemanticResponseParser().parse("not json")

    assert parsed.valid_json is False
    assert parsed.candidates == []
    assert parsed.notes


def test_semantic_validator_rejects_invented_path():
    rule = next(rule for rule in load_rules() if rule.id == "LOG-003")
    candidate = FindingCandidate(
        rule_id=rule.id,
        path="invented.py",
        line=1,
        message="Problem.",
        evidence="password",
        analyzer="semantic",
        confidence=0.9,
        language="python",
    )
    validator = SemanticFindingValidator([rule], [], [], _settings())

    findings, notes = validator.validate([candidate])

    assert findings == []
    assert "path was not scanned" in notes[0]


def test_semantic_validator_accepts_valid_candidate():
    rule = next(rule for rule in load_rules() if rule.id == "LOG-003")
    code_file = CodeFile(
        path=Path("app.py"),
        relative_path="app.py",
        language="python",
        text="logging.info('password')\n",
    )
    snippet = Snippet(
        path="app.py",
        language="python",
        start_line=1,
        end_line=1,
        text="logging.info('password')",
        reason="test",
    )
    candidate = FindingCandidate(
        rule_id=rule.id,
        path="app.py",
        line=1,
        message="Sensitive logging.",
        evidence="password",
        analyzer="semantic",
        confidence=0.9,
        language="python",
    )

    findings, notes = SemanticFindingValidator(
        [rule],
        [code_file],
        [snippet],
        _settings(),
    ).validate([candidate])

    assert notes == []
    assert len(findings) == 1
    assert findings[0].severity == rule.severity
