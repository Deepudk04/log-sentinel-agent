from datetime import UTC, datetime

from logsentinel.domain import ScanResult
from logsentinel.reporting import render_markdown
from logsentinel.rule_catalog import load_rules


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
    )

    markdown = render_markdown(result)

    assert "# LogSentinel Report" in markdown
    assert "LOG-003" in markdown
    assert "OWASP Logging Cheat Sheet" in markdown
