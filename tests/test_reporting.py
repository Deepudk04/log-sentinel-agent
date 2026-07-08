from datetime import UTC, datetime

from domain import Finding, ScanResult
from reporting import render_html_report, render_json_report, render_markdown, render_sarif
from rule_catalog import load_rules


def test_report_includes_rule_catalog_and_sources():
    result = ScanResult(
        repository="repo",
        generated_at=datetime(2026, 7, 7, tzinfo=UTC),
        scanned_files=0,
        skipped=[],
        findings=[],
        snippets_sent=0,
        rules=list(load_rules()),
        notes=[],
        markdown_report="",
        metrics={"total_loc": 4},
        config_summary={"report_formats": ("markdown", "json")},
        semantic_enabled=False,
        total_loc=4,
    )

    markdown = render_markdown(result)

    assert "# LogSentinel Report" in markdown
    assert "LOG-003" in markdown
    assert "OWASP Logging Cheat Sheet" in markdown


def test_json_and_sarif_reports_include_findings():
    rule = next(rule for rule in load_rules() if rule.id == "LOG-003")
    result = ScanResult(
        repository="repo",
        generated_at=datetime(2026, 7, 7, tzinfo=UTC),
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
                line=2,
                message="Sensitive logging.",
                evidence="password='secret-value'",
                recommendation=rule.recommendation,
                confidence=0.9,
                source_refs=rule.source_refs,
                fingerprint="abc123",
            )
        ],
        snippets_sent=0,
        rules=[rule],
        notes=[],
        markdown_report="",
        metrics={"total_loc": 4},
        config_summary={"report_formats": ("markdown", "json")},
        semantic_enabled=False,
        total_loc=4,
    )

    json_report = render_json_report(result)
    sarif_report = render_sarif(result)
    html_report = render_html_report(result)

    assert '"rule_id": "LOG-003"' in json_report
    assert '"total_loc_scanned": 4' in json_report
    assert '"semantic_enabled": false' in json_report
    assert '"config_summary"' in json_report
    assert '"metrics"' in json_report
    assert "secret-value" not in json_report
    assert '"version": "2.1.0"' in sarif_report
    assert '"ruleId": "LOG-003"' in sarif_report
    assert "<h1>LogSentinel Report</h1>" in html_report
    assert "secret-value" not in html_report
