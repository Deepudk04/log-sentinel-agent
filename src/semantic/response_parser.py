from __future__ import annotations

import json
import re
from dataclasses import dataclass

from domain import FindingCandidate


@dataclass(frozen=True)
class ParsedSemanticResponse:
    candidates: list[FindingCandidate]
    notes: list[str]
    valid_json: bool


class SemanticResponseParser:
    def parse(self, text: str) -> ParsedSemanticResponse:
        try:
            payload = json.loads(_extract_json(text))
        except json.JSONDecodeError as exc:
            return ParsedSemanticResponse(
                candidates=[],
                notes=[f"Semantic analysis response was not valid JSON: {exc}"],
                valid_json=False,
            )

        candidates: list[FindingCandidate] = []
        notes: list[str] = []
        for raw in payload.get("findings", []):
            if not isinstance(raw, dict):
                notes.append("Semantic finding skipped because it was not an object.")
                continue
            candidates.append(
                FindingCandidate(
                    rule_id=str(raw.get("rule_id", "")).strip(),
                    path=str(raw.get("path", "")).strip(),
                    line=_safe_int(raw.get("line")) or 0,
                    message=_clean(raw.get("message"), "Semantic rule matched."),
                    evidence=_clean(raw.get("evidence"), ""),
                    recommendation=_clean(raw.get("recommendation"), ""),
                    analyzer="semantic",
                    confidence=_safe_float(raw.get("confidence"), 0.0),
                    language=str(raw.get("language", "")).strip(),
                    deterministic_signals=[],
                )
            )
        return ParsedSemanticResponse(candidates=candidates, notes=notes, valid_json=True)


def _extract_json(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?", "", stripped).strip()
        stripped = re.sub(r"```$", "", stripped).strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end < start:
        return stripped
    return stripped[start : end + 1]


def _safe_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _safe_float(value: object, default: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _clean(value: object, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default
