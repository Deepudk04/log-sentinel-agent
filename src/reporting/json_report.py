from __future__ import annotations

import json
from typing import Any

from domain import Finding, ScanResult, SourceRef
from semantic.redactor import SecretRedactor


def render_json_report(result: ScanResult) -> str:
    payload = {
        "tool": {"name": "LogSentinel", "version": "0.1.0"},
        "repository": result.repository,
        "generated_at": result.generated_at.isoformat(),
        "summary": {
            "repo_path": result.repository,
            "files_scanned": result.scanned_files,
            "total_loc_scanned": result.total_loc,
            "findings": len(result.findings),
            "snippets_sent": result.snippets_sent,
            "skipped_files": len(result.skipped),
            "semantic_enabled": result.semantic_enabled,
            "findings_by_severity": _counts_by_severity(result.findings),
        },
        "config_summary": _json_safe(result.config_summary),
        "metrics": _json_safe(result.metrics),
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


def _json_safe(value: object) -> object:
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value
