from pathlib import Path

from domain import CodeFile, FindingCandidate
from parsing.treesitter_service import TreeSitterService
from rules.registry import analyzers_for_language


class _NoParserService(TreeSitterService):
    def _get_parser(self, language: str):
        self._import_error = f"No parser for {language}"
        return None


def test_python_rule_engine_emits_finding_candidates():
    code_file = CodeFile(
        path=Path("app.py"),
        relative_path="app.py",
        language="python",
        text='import logging\nlogging.info("password=%s", password)\n',
    )
    context = _NoParserService().analyze_file(code_file)
    candidates = [
        candidate
        for analyzer in analyzers_for_language("python")
        for candidate in analyzer.analyze(context)
    ]

    assert any(isinstance(candidate, FindingCandidate) for candidate in candidates)
    assert any(candidate.rule_id == "LOG-003" for candidate in candidates)
    assert all(candidate.language == "python" for candidate in candidates)


def test_registry_filters_analyzers_by_language():
    python_analyzers = analyzers_for_language("python")
    java_analyzers = analyzers_for_language("java")

    assert python_analyzers
    assert java_analyzers
    assert all("python" in analyzer.languages for analyzer in python_analyzers)
    assert all("java" in analyzer.languages for analyzer in java_analyzers)
