from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import replace

from domain import CodeFile, Finding
from reporting import SEVERITY_ORDER

NEXT_LINE_SUPPRESS_RE = re.compile(r"logsentinel-disable-next-line\s+([A-Z]+-\d+)")
FILE_SUPPRESS_RE = re.compile(r"logsentinel-disable-file\s+([A-Z]+-\d+)")


class PostProcessor:
    def process(self, findings: list[Finding], files: list[CodeFile]) -> list[Finding]:
        suppressed = _suppression_index(files)
        processed: list[Finding] = []
        seen: set[str] = set()
        for finding in findings:
            if _is_suppressed(finding, suppressed):
                continue
            fingerprint = _fingerprint(finding)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            processed.append(replace(finding, fingerprint=fingerprint))
        return sorted(
            processed,
            key=lambda item: (SEVERITY_ORDER[item.severity], item.path, item.line, item.rule_id),
        )

    @staticmethod
    def metrics(findings: list[Finding], files: list[CodeFile]) -> dict[str, object]:
        severity_counts = Counter(finding.severity for finding in findings)
        rule_counts = Counter(finding.rule_id for finding in findings)
        language_counts = Counter(file.language for file in files)
        return {
            "findings_by_severity": dict(severity_counts),
            "findings_by_rule": dict(rule_counts),
            "files_by_language": dict(language_counts),
            "total_loc": sum(len(file.lines) for file in files),
        }


def _suppression_index(files: list[CodeFile]) -> dict[tuple[str, str], set[int] | None]:
    suppressions: dict[tuple[str, str], set[int] | None] = {}
    for code_file in files:
        for idx, line in enumerate(code_file.lines, start=1):
            file_match = FILE_SUPPRESS_RE.search(line)
            if file_match:
                suppressions[(code_file.relative_path, file_match.group(1))] = None
            next_match = NEXT_LINE_SUPPRESS_RE.search(line)
            if next_match:
                key = (code_file.relative_path, next_match.group(1))
                if key in suppressions and suppressions[key] is None:
                    continue
                existing = suppressions.get(key)
                lines = existing or set()
                lines.add(idx + 1)
                suppressions[key] = lines
    return suppressions


def _is_suppressed(
    finding: Finding,
    suppressions: dict[tuple[str, str], set[int] | None],
) -> bool:
    key = (finding.path, finding.rule_id)
    if key not in suppressions:
        return False
    value = suppressions[key]
    return value is None or (value is not None and finding.line in value)


def _fingerprint(finding: Finding) -> str:
    evidence_hash = hashlib.sha256(finding.evidence.strip().lower().encode()).hexdigest()[:16]
    line_bucket = finding.line // 5
    raw = f"{finding.rule_id}:{finding.path}:{line_bucket}:{evidence_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]
