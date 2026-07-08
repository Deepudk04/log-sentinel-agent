from __future__ import annotations

import json
from dataclasses import dataclass

from config import Settings
from domain import CodeFile, Finding, Rule, Snippet
from observability import get_logger
from semantic.response_parser import SemanticResponseParser
from semantic.snippet_builder import SnippetBuilder
from semantic.validator import SemanticFindingValidator

logger = get_logger("semantic")


@dataclass(frozen=True)
class SemanticResult:
    findings: list[Finding]
    notes: list[str]


class GeminiSemanticAnalyzer:
    def __init__(self, settings: Settings, rules: list[Rule]) -> None:
        self.settings = settings
        self.rules = {rule.id: rule for rule in rules}

    def analyze(
        self,
        snippets: list[Snippet],
        files: list[CodeFile] | None = None,
        deterministic_findings: list[Finding] | None = None,
    ) -> SemanticResult:
        if not snippets:
            logger.info("Semantic analysis skipped: no snippets collected")
            return SemanticResult(
                findings=[],
                notes=["Semantic analysis skipped: no snippets collected."],
            )
        if not self.settings.gemini_api_key:
            logger.warning("Semantic analysis skipped: Gemini API key is not set")
            return SemanticResult(
                findings=[],
                notes=["Semantic analysis skipped: GEMINI_API_KEY or GOOGLE_API_KEY is not set."],
            )

        safe_snippets = SnippetBuilder(
            redact_before_llm=self.settings.redact_before_llm,
            max_snippets_per_file=self.settings.max_snippets_per_file,
        ).redact_existing(snippets)
        prompt = self._build_prompt(safe_snippets)
        logger.info(
            "Calling Gemini semantic analyzer: model=%s snippets=%s prompt_chars=%s",
            self.settings.gemini_model,
            len(safe_snippets),
            len(prompt),
        )
        try:
            from google import genai
        except Exception as exc:  # pragma: no cover - optional dependency guard
            logger.error("Semantic analysis skipped: google-genai unavailable: %s", exc)
            return SemanticResult(
                findings=[],
                notes=[f"Semantic analysis skipped: google-genai unavailable ({exc})."],
            )

        client = genai.Client(api_key=self.settings.gemini_api_key)
        parser = SemanticResponseParser()
        parsed = None
        notes: list[str] = []
        try:
            for attempt in range(2):
                response = client.models.generate_content(
                    model=self.settings.gemini_model,
                    contents=prompt,
                    config={"temperature": 0, "response_mime_type": "application/json"},
                )
                text = getattr(response, "text", "") or ""
                logger.info("Gemini response received: response_chars=%s", len(text))
                parsed = parser.parse(text)
                notes.extend(parsed.notes)
                if parsed.valid_json:
                    break
                if attempt == 0:
                    logger.warning("Retrying semantic analysis once after invalid JSON")
        except Exception as exc:  # pragma: no cover - network/API dependent
            logger.error("Semantic analysis failed: %s", exc)
            return SemanticResult(findings=[], notes=[f"Semantic analysis failed: {exc}"])
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                close()
                logger.debug("Gemini client closed")

        if parsed is None or not parsed.valid_json:
            return SemanticResult(findings=[], notes=notes)
        validator = SemanticFindingValidator(
            list(self.rules.values()),
            files or [],
            safe_snippets,
            self.settings,
            deterministic_findings,
        )
        findings, validation_notes = validator.validate(parsed.candidates)
        notes.extend(validation_notes)
        return SemanticResult(findings=findings, notes=notes)

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
                "snippet_id": snippet.snippet_id,
                "path": snippet.path,
                "language": snippet.language,
                "start_line": snippet.start_line,
                "end_line": snippet.end_line,
                "symbol": snippet.symbol,
                "candidate_rule_ids": snippet.candidate_rule_ids,
                "deterministic_signals": snippet.deterministic_signals,
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
