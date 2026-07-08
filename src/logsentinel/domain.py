from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
AnalysisMode = Literal["deterministic", "semantic", "hybrid"]


@dataclass(frozen=True)
class SourceRef:
    title: str
    url: str
    line_start: int | None = None
    line_end: int | None = None
    note: str | None = None

    @property
    def label(self) -> str:
        if self.line_start and self.line_end:
            return f"{self.title} lines {self.line_start}-{self.line_end}"
        if self.line_start:
            return f"{self.title} line {self.line_start}"
        return self.title


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity: Severity
    analysis_mode: AnalysisMode
    languages: list[str]
    description: str
    recommendation: str
    standards: list[str]
    source_refs: list[SourceRef]
    semantic_prompt: str
    deterministic_signals: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CodeFile:
    path: Path
    relative_path: str
    language: str
    text: str
    file_hash: str = ""

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_title: str
    severity: Severity
    category: str
    analyzer: Literal["deterministic", "semantic"]
    path: str
    line: int
    message: str
    evidence: str
    recommendation: str
    confidence: float
    source_refs: list[SourceRef]


@dataclass(frozen=True)
class Snippet:
    path: str
    language: str
    start_line: int
    end_line: int
    text: str
    reason: str


@dataclass(frozen=True)
class ScanRequest:
    repo_path: Path
    use_semantic: bool = True
    max_files: int | None = None
    max_snippets: int | None = None
    write_report: bool = True


@dataclass
class ScanResult:
    repository: str
    generated_at: datetime
    scanned_files: int
    skipped: list[str]
    findings: list[Finding]
    snippets_sent: int
    rules: list[Rule]
    notes: list[str]
    markdown_report: str
    report_path: str | None = None

    @classmethod
    def empty(cls, repository: str, rules: list[Rule]) -> "ScanResult":
        return cls(
            repository=repository,
            generated_at=datetime.now(UTC),
            scanned_files=0,
            skipped=[],
            findings=[],
            snippets_sent=0,
            rules=rules,
            notes=[],
            markdown_report="",
        )


def source_ref_from_dict(raw: dict[str, Any]) -> SourceRef:
    return SourceRef(
        title=raw["title"],
        url=raw["url"],
        line_start=raw.get("line_start"),
        line_end=raw.get("line_end"),
        note=raw.get("note"),
    )


def rule_from_dict(raw: dict[str, Any]) -> Rule:
    return Rule(
        id=raw["id"],
        title=raw["title"],
        category=raw["category"],
        severity=raw["severity"],
        analysis_mode=raw["analysis_mode"],
        languages=list(raw.get("languages", [])),
        description=raw["description"],
        recommendation=raw["recommendation"],
        standards=list(raw.get("standards", [])),
        source_refs=[source_ref_from_dict(item) for item in raw.get("source_refs", [])],
        semantic_prompt=raw["semantic_prompt"],
        deterministic_signals=list(raw.get("deterministic_signals", [])),
    )
