from __future__ import annotations

from html import escape

from domain import ScanResult
from semantic.redactor import SecretRedactor


def render_html_report(result: ScanResult) -> str:
    redactor = SecretRedactor()
    findings = "\n".join(
        "<section>"
        f"<h2>{escape(finding.severity.upper())} {escape(finding.rule_id)}</h2>"
        f"<p><strong>{escape(finding.path)}:{finding.line}</strong></p>"
        f"<p>{escape(finding.message)}</p>"
        f"<pre>{escape(redactor.redact(finding.evidence))}</pre>"
        "</section>"
        for finding in result.findings
    )
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<title>LogSentinel Report</title></head><body>"
        "<h1>LogSentinel Report</h1>"
        f"<p>Repository: {escape(result.repository)}</p>"
        f"<p>Files scanned: {result.scanned_files}</p>"
        f"<p>LOC scanned: {result.total_loc}</p>"
        f"<p>Findings: {len(result.findings)}</p>"
        f"{findings or '<p>No findings were detected.</p>'}"
        "</body></html>"
    )
