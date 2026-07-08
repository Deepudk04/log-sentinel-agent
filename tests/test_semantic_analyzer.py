from concurrent.futures import TimeoutError
from time import sleep

import pytest

from domain import Snippet
from rule_catalog import load_rules
from semantic.analyzer import _call_gemini_with_timeout
from semantic.prompt_builder import SemanticPromptBuilder


def test_prompt_builder_includes_strict_constraints_and_cache_key_is_stable():
    snippets = [
        Snippet(
            path="app.py",
            language="python",
            start_line=1,
            end_line=2,
            text="logger.info('login failed')",
            reason="test",
            snippet_id="abc",
            candidate_rule_ids=["LOG-001"],
        )
    ]
    builder = SemanticPromptBuilder(list(load_rules()))

    prompt = builder.build(snippets)

    assert "Do not invent rules, paths, line numbers, or facts" in prompt
    assert "Return strict JSON" in prompt
    assert builder.cache_key(snippets, "model") == builder.cache_key(snippets, "model")


def test_gemini_call_timeout_raises_timeout_error():
    class SlowModels:
        @staticmethod
        def generate_content(**kwargs):
            sleep(0.2)
            return object()

    class SlowClient:
        models = SlowModels()

    with pytest.raises(TimeoutError):
        _call_gemini_with_timeout(
            SlowClient(),
            model="model",
            prompt="prompt",
            timeout_seconds=0.01,
        )
