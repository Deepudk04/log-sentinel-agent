from __future__ import annotations

import json
from hashlib import sha256

from domain import Rule, Snippet

RULE_CATALOG_VERSION = "owasp-logging-exception-v1"


class SemanticPromptBuilder:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    def build(self, snippets: list[Snippet]) -> str:
        return (
            "You are LogSentinel, a code security reviewer focused only on logging and "
            "exception handling. Use only the provided OWASP-derived rule IDs. Do not invent "
            "rules, paths, line numbers, or facts. Analyze only the snippets. If evidence is "
            "insufficient, return no finding for that case.\n\n"
            "Return strict JSON with this shape:\n"
            "{\"findings\":[{\"rule_id\":\"LOG-001\",\"path\":\"file.py\",\"line\":12,"
            "\"message\":\"short problem\",\"evidence\":\"short evidence from snippet\","
            "\"recommendation\":\"specific fix\",\"confidence\":0.0}]}\n\n"
            f"Rules:\n{json.dumps(self._semantic_rules(), indent=2)}\n\n"
            f"Snippets:\n{json.dumps(self.snippet_payload(snippets), indent=2)}"
        )

    def cache_key(self, snippets: list[Snippet], model_name: str) -> str:
        raw = {
            "catalog_version": RULE_CATALOG_VERSION,
            "model": model_name,
            "rules": [rule.id for rule in self.rules],
            "snippets": self.snippet_payload(snippets),
        }
        return sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()

    def snippet_payload(self, snippets: list[Snippet]) -> list[dict[str, object]]:
        return [
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

    def _semantic_rules(self) -> list[dict[str, object]]:
        return [
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity,
                "description": rule.description,
                "semantic_check": rule.semantic_prompt,
                "recommendation": rule.recommendation,
                "standards": rule.standards,
            }
            for rule in self.rules
            if rule.analysis_mode in {"semantic", "hybrid"}
        ]
