from __future__ import annotations

import json
from typing import Any

from domain import Finding, ScanResult


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
    payload: dict[str, Any] = {
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
