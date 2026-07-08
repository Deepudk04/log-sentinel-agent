from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from domain import Finding, ScanResult, SourceRef
from semantic.redactor import SecretRedactor

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


def render_json_report(result: ScanResult) -> str:
    payload = {
        "tool": {"name": "LogSentinel", "version": "0.1.0"},
        "repository": result.repository,
        "generated_at": result.generated_at.isoformat(),
        "summary": {
            "files_scanned": result.scanned_files,
            "findings": len(result.findings),
            "snippets_sent": result.snippets_sent,
            "skipped_files": len(result.skipped),
            "findings_by_severity": _counts_by_severity(result.findings),
        },
        "findings": [_finding_dict(finding) for finding in result.findings],
        "notes": result.notes,
        "skipped": result.skipped,
        "rules": [
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity,
                "category": rule.category,
                "analysis_mode": rule.analysis_mode,
                "standards": rule.standards,
                "source_refs": [_source_ref_dict(ref) for ref in rule.source_refs],
            }
            for rule in result.rules
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def render_sarif(result: ScanResult) -> str:
    rules = [
        {
            "id": rule.id,
            "name": rule.title,
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "help": {"text": rule.recommendation},
            "properties": {
                "category": rule.category,
                "severity": rule.severity,
                "standards": rule.standards,
            },
        }
        for rule in result.rules
    ]
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LogSentinel",
                        "informationUri": "https://github.com/Deepudk04/log-sentinel-agent",
                        "rules": rules,
                    }
                },
                "results": [_sarif_result(finding) for finding in result.findings],
            }
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def write_reports(result: ScanResult, output_dir: Path, formats: tuple[str, ...]) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    rendered = {
        "markdown": result.markdown_report or render_markdown(result),
        "json": render_json_report(result),
        "sarif": render_sarif(result),
    }
    extensions = {"markdown": "md", "json": "json", "sarif": "sarif"}
    paths: dict[str, str] = {}
    for report_format in formats:
        normalized = report_format.strip().lower()
        if normalized not in rendered:
            continue
        path = output_dir / f"logsentinel-{timestamp}.{extensions[normalized]}"
        path.write_text(rendered[normalized], encoding="utf-8")
        paths[normalized] = str(path)
    return paths


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


def _finding_dict(finding: Finding) -> dict[str, Any]:
    redactor = SecretRedactor()
    return {
        "rule_id": finding.rule_id,
        "rule_title": finding.rule_title,
        "severity": finding.severity,
        "category": finding.category,
        "analyzer": finding.analyzer,
        "path": finding.path,
        "line": finding.line,
        "message": finding.message,
        "evidence": redactor.redact(finding.evidence),
        "recommendation": finding.recommendation,
        "confidence": finding.confidence,
        "fingerprint": finding.fingerprint,
        "source_refs": [_source_ref_dict(ref) for ref in finding.source_refs],
    }


def _source_ref_dict(ref: SourceRef) -> dict[str, Any]:
    return {
        "title": ref.title,
        "url": ref.url,
        "line_start": ref.line_start,
        "line_end": ref.line_end,
        "note": ref.note,
    }


def _sarif_result(finding: Finding) -> dict[str, Any]:
    level = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }[finding.severity]
    return {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": {"startLine": finding.line},
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": finding.fingerprint or "",
        },
        "properties": {
            "confidence": finding.confidence,
            "analyzer": finding.analyzer,
            "recommendation": finding.recommendation,
        },
    }
