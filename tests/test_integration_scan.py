from pathlib import Path

import agent
from config import Settings
from domain import Finding, ScanRequest
from rule_catalog import load_rules
from semantic.analyzer import SemanticResult


def _settings(output_dir: Path) -> Settings:
    return Settings(
        gemini_api_key=None,
        gemini_model="test-model",
        output_dir=output_dir,
        max_file_bytes=500_000,
        max_files=100,
        max_snippets=40,
        languages_include=("python", "java"),
        languages_exclude=(),
        ignore_patterns=(),
        max_snippets_per_file=20,
        semantic_enabled=True,
        semantic_provider="gemini",
        semantic_min_confidence=0.70,
        redact_before_llm=True,
        semantic_timeout_seconds=5,
        semantic_cache_enabled=False,
        report_formats=("markdown",),
        fail_on_severity=None,
    )


def test_scan_vulnerable_python_repo_no_semantic(tmp_path):
    result = agent.run_scan(
        ScanRequest(
            repo_path=Path("evaluation/corpus/python/true_positive"),
            use_semantic=False,
            write_report=False,
        ),
        settings=_settings(tmp_path),
    )

    assert result.scanned_files == 1
    assert {finding.rule_id for finding in result.findings} >= {"LOG-003", "ERR-003"}
    assert "Semantic analysis disabled for this scan." in result.notes


def test_scan_clean_python_repo_no_semantic(tmp_path):
    result = agent.run_scan(
        ScanRequest(
            repo_path=Path("evaluation/corpus/python/false_positive"),
            use_semantic=False,
            write_report=False,
        ),
        settings=_settings(tmp_path),
    )

    assert result.scanned_files == 1
    assert result.findings == []


def test_scan_vulnerable_java_repo_no_semantic(tmp_path):
    result = agent.run_scan(
        ScanRequest(
            repo_path=Path("evaluation/corpus/java/true_positive"),
            use_semantic=False,
            write_report=False,
        ),
        settings=_settings(tmp_path),
    )

    assert result.scanned_files == 1
    assert any(finding.rule_id == "LOG-005" for finding in result.findings)


def test_scan_clean_java_repo_no_semantic(tmp_path):
    result = agent.run_scan(
        ScanRequest(
            repo_path=Path("evaluation/corpus/java/false_positive"),
            use_semantic=False,
            write_report=False,
        ),
        settings=_settings(tmp_path),
    )

    assert result.scanned_files == 1
    assert result.findings == []


def test_scan_semantic_mode_with_mocked_gemini(monkeypatch, tmp_path):
    rule = next(rule for rule in load_rules() if rule.id == "LOG-001")

    class FakeSemanticAnalyzer:
        def __init__(self, settings, rules):
            self.settings = settings
            self.rules = rules

        def analyze(self, snippets, files=None, deterministic_findings=None):
            return SemanticResult(
                findings=[
                    Finding(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        severity=rule.severity,
                        category=rule.category,
                        analyzer="semantic",
                        path="clean_app.py",
                        line=7,
                        message="Security event lacks enough context.",
                        evidence="logger.warning(\"login failed\", extra={\"username\": username})",
                        recommendation=rule.recommendation,
                        confidence=0.9,
                        source_refs=rule.source_refs,
                    )
                ],
                notes=["Mock semantic analyzer used."],
            )

    settings = _settings(tmp_path)
    monkeypatch.setattr(agent, "GeminiSemanticAnalyzer", FakeSemanticAnalyzer)

    result = agent.run_scan(
        ScanRequest(
            repo_path=Path("evaluation/corpus/python/false_positive"),
            use_semantic=True,
            write_report=False,
        ),
        settings=settings,
    )

    assert any(finding.analyzer == "semantic" for finding in result.findings)
    assert "Mock semantic analyzer used." in result.notes


def test_scan_generates_markdown_json_sarif_and_html_reports(tmp_path):
    result = agent.run_scan(
        ScanRequest(
            repo_path=Path("evaluation/corpus/python/true_positive"),
            use_semantic=False,
            write_report=True,
            formats=("markdown", "json", "sarif", "html"),
        ),
        settings=_settings(tmp_path),
    )

    assert set(result.report_paths) == {"markdown", "json", "sarif", "html"}
    for report_path in result.report_paths.values():
        assert Path(report_path).exists()
