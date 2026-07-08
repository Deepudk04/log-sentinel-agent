from __future__ import annotations

import json
import re
from dataclasses import dataclass

from logsentinel.config import Settings
from logsentinel.domain import Finding, Rule, Snippet


@dataclass(frozen=True)
class SemanticResult:
    findings: list[Finding]
    notes: list[str]


class GeminiSemanticAnalyzer:
    def __init__(self, settings: Settings, rules: list[Rule]) -> None:
        self.settings = settings
        self.rules = {rule.id: rule for rule in rules}

    def analyze(self, snippets: list[Snippet]) -> SemanticResult:
        if not snippets:
            return SemanticResult(findings=[], notes=["Semantic analysis skipped: no snippets collected."])
        if not self.settings.gemini_api_key:
            return SemanticResult(
                findings=[],
                notes=["Semantic analysis skipped: GEMINI_API_KEY or GOOGLE_API_KEY is not set."],
            )

        prompt = self._build_prompt(snippets)
        try:
            from google import genai
        except Exception as exc:  # pragma: no cover - optional dependency guard
            return SemanticResult(
                findings=[],
                notes=[f"Semantic analysis skipped: google-genai unavailable ({exc})."],
            )

        client = genai.Client(api_key=self.settings.gemini_api_key)
        try:
            response = client.models.generate_content(
                model=self.settings.gemini_model,
                contents=prompt,
                config={"temperature": 0, "response_mime_type": "application/json"},
            )
            text = getattr(response, "text", "") or ""
        except Exception as exc:  # pragma: no cover - network/API dependent
            return SemanticResult(findings=[], notes=[f"Semantic analysis failed: {exc}"])
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                close()

        return self._parse_response(text, snippets)

    def _build_prompt(self, snippets: list[Snippet]) -> str:
        semantic_rules = [
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity,
                "description": rule.description,
                "semantic_check": rule.semantic_prompt,
                "recommendation": rule.recommendation,
                "standards": rule.standards,
            }
            for rule in self.rules.values()
            if rule.analysis_mode in {"semantic", "hybrid"}
        ]
        snippet_payload = [
            {
                "path": snippet.path,
                "language": snippet.language,
                "start_line": snippet.start_line,
                "end_line": snippet.end_line,
                "reason": snippet.reason,
                "text": snippet.text,
            }
            for snippet in snippets
        ]
        return (
            "You are LogSentinel, a code security reviewer focused only on logging and "
            "exception handling. Use only the provided OWASP-derived rule IDs. Do not invent "
            "rules, paths, or facts. Analyze only the snippets. If evidence is insufficient, "
            "return no finding for that case.\n\n"
            "Return strict JSON with this shape:\n"
            "{\"findings\":[{\"rule_id\":\"LOG-001\",\"path\":\"file.py\",\"line\":12,"
            "\"message\":\"short problem\",\"evidence\":\"short evidence from snippet\","
            "\"recommendation\":\"specific fix\",\"confidence\":0.0}]}\n\n"
            f"Rules:\n{json.dumps(semantic_rules, indent=2)}\n\n"
            f"Snippets:\n{json.dumps(snippet_payload, indent=2)}"
        )

    def _parse_response(self, text: str, snippets: list[Snippet]) -> SemanticResult:
        notes: list[str] = []
        try:
            payload = json.loads(_extract_json(text))
        except json.JSONDecodeError as exc:
            return SemanticResult(
                findings=[],
                notes=[f"Semantic analysis response was not valid JSON: {exc}"],
            )

        valid_paths = {snippet.path for snippet in snippets}
        snippet_by_path = {snippet.path: snippet for snippet in snippets}
        findings: list[Finding] = []

        for raw in payload.get("findings", []):
            rule_id = str(raw.get("rule_id", "")).strip()
            if rule_id not in self.rules:
                notes.append(f"Semantic finding skipped because rule_id is not in catalog: {rule_id}")
                continue
            path = str(raw.get("path", "")).strip()
            if path not in valid_paths:
                notes.append(f"Semantic finding skipped because path was not in snippets: {path}")
                continue
            rule = self.rules[rule_id]
            line = _safe_int(raw.get("line")) or snippet_by_path[path].start_line
            confidence = min(max(float(raw.get("confidence", 0.55)), 0.0), 1.0)
            if confidence < 0.55:
                continue
            findings.append(
                Finding(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    severity=rule.severity,
                    category=rule.category,
                    analyzer="semantic",
                    path=path,
                    line=line,
                    message=_clean(raw.get("message"), "Semantic rule matched."),
                    evidence=_clean(raw.get("evidence"), ""),
                    recommendation=_clean(raw.get("recommendation"), rule.recommendation),
                    confidence=confidence,
                    source_refs=rule.source_refs,
                )
            )

        return SemanticResult(findings=findings, notes=notes)


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


def _clean(value: object, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default
