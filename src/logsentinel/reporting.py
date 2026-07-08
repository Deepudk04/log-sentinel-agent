from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from logsentinel.domain import Finding, ScanResult, SourceRef
from logsentinel.semantic.redactor import SecretRedactor

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def render_markdown(result: ScanResult) -> str:
    lines: list[str] = [
        "# LogSentinel Report",
        "",
        f"- Repository: `{result.repository}`",
        f"- Generated: `{result.generated_at.isoformat()}`",
        f"- Files scanned: `{result.scanned_files}`",
        f"- Findings: `{len(result.findings)}`",
        f"- Snippets sent to semantic analyzer: `{result.snippets_sent}`",
        "",
    ]

    if result.notes:
        lines.extend(["## Notes", ""])
        lines.extend(f"- {note}" for note in result.notes)
        lines.append("")

    lines.extend(["## Summary", ""])
    counts = _counts_by_severity(result.findings)
    for severity in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"- {severity.title()}: `{counts.get(severity, 0)}`")
    lines.append("")

    lines.extend(["## Findings", ""])
    if not result.findings:
        lines.extend(["No findings were detected by the enabled analyzers.", ""])
    else:
        for finding in sorted(
            result.findings,
            key=lambda item: (SEVERITY_ORDER[item.severity], item.path, item.line, item.rule_id),
        ):
            lines.extend(_finding_markdown(finding))

    lines.extend(["## Rule Catalog", ""])
    for rule in result.rules:
        lines.extend(
            [
                f"### {rule.id}: {rule.title}",
                "",
                f"- Severity: `{rule.severity}`",
                f"- Analyzer: `{rule.analysis_mode}`",
                f"- Category: `{rule.category}`",
                f"- Standards: {', '.join(rule.standards)}",
                f"- Description: {rule.description}",
                f"- Sources: {_source_refs(rule.source_refs)}",
                "",
            ]
        )

    if result.skipped:
        lines.extend(["## Skipped Files", ""])
        lines.extend(f"- {item}" for item in result.skipped)
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_report(markdown: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    path = output_dir / f"logsentinel-{timestamp}.md"
    path.write_text(markdown, encoding="utf-8")
    return path


def _finding_markdown(finding: Finding) -> list[str]:
    evidence = SecretRedactor().redact(finding.evidence).replace("```", "'''")
    return [
        f"### {finding.severity.upper()} {finding.rule_id}: {finding.rule_title}",
        "",
        f"- Location: `{finding.path}:{finding.line}`",
        f"- Analyzer: `{finding.analyzer}`",
        f"- Confidence: `{finding.confidence:.2f}`",
        f"- Problem: {finding.message}",
        f"- Recommendation: {finding.recommendation}",
        f"- Sources: {_source_refs(finding.source_refs)}",
        "",
        "```text",
        evidence,
        "```",
        "",
    ]


def _source_refs(source_refs: list[SourceRef]) -> str:
    return ", ".join(f"[{ref.label}]({ref.url})" for ref in source_refs)


def _counts_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts
