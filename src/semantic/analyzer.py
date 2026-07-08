from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass

from config import Settings
from domain import CodeFile, Finding, Rule, Snippet
from observability import get_logger
from semantic.prompt_builder import SemanticPromptBuilder
from semantic.response_parser import SemanticResponseParser
from semantic.snippet_builder import SnippetBuilder
from semantic.validator import SemanticFindingValidator

logger = get_logger("semantic")
_SEMANTIC_CACHE: dict[str, str] = {}


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
        prompt_builder = SemanticPromptBuilder(list(self.rules.values()))
        prompt = prompt_builder.build(safe_snippets)
        cache_key = prompt_builder.cache_key(safe_snippets, self.settings.gemini_model)
        logger.info(
            "Calling Gemini semantic analyzer: model=%s snippets=%s prompt_chars=%s cache=%s",
            self.settings.gemini_model,
            len(safe_snippets),
            len(prompt),
            "enabled" if self.settings.semantic_cache_enabled else "disabled",
        )
        try:
            from google import genai
        except Exception as exc:  # pragma: no cover - optional dependency guard
            logger.error("Semantic analysis skipped: google-genai unavailable: %s", exc)
            return SemanticResult(
                findings=[],
                notes=[f"Semantic analysis skipped: google-genai unavailable ({exc})."],
            )

        parser = SemanticResponseParser()
        parsed = None
        notes: list[str] = []
        if self.settings.semantic_cache_enabled and cache_key in _SEMANTIC_CACHE:
            logger.info("Semantic cache hit: key=%s", cache_key[:12])
            parsed = parser.parse(_SEMANTIC_CACHE[cache_key])
            notes.extend(parsed.notes)
        else:
            client = genai.Client(api_key=self.settings.gemini_api_key)
            try:
                for attempt in range(2):
                    text = _call_gemini_with_timeout(
                        client,
                        model=self.settings.gemini_model,
                        prompt=prompt,
                        timeout_seconds=self.settings.semantic_timeout_seconds,
                    )
                    logger.info("Gemini response received: response_chars=%s", len(text))
                    parsed = parser.parse(text)
                    notes.extend(parsed.notes)
                    if parsed.valid_json:
                        if self.settings.semantic_cache_enabled:
                            _SEMANTIC_CACHE[cache_key] = text
                            logger.debug("Semantic cache stored: key=%s", cache_key[:12])
                        break
                    if attempt == 0:
                        logger.warning("Retrying semantic analysis once after invalid JSON")
            except TimeoutError:
                logger.error(
                    "Semantic analysis timed out after %s seconds",
                    self.settings.semantic_timeout_seconds,
                )
                return SemanticResult(
                    findings=[],
                    notes=[
                        "Semantic analysis failed: timed out after "
                        f"{self.settings.semantic_timeout_seconds} seconds."
                    ],
                )
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


def _call_gemini_with_timeout(
    client,
    *,
    model: str,
    prompt: str,
    timeout_seconds: int,
) -> str:
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(
            client.models.generate_content,
            model=model,
            contents=prompt,
            config={"temperature": 0, "response_mime_type": "application/json"},
        )
        response = future.result(timeout=timeout_seconds)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    return getattr(response, "text", "") or ""
