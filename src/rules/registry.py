from __future__ import annotations

from rules.base import RuleAnalyzer
from rules.java.console_logging import JavaConsoleLoggingRule
from rules.java.sensitive_logging import JavaSensitiveLoggingRule
from rules.java.swallowed_exception import JavaSwallowedExceptionRule
from rules.java.unsafe_error_response import JavaUnsafeErrorResponseRule
from rules.python.sensitive_logging import PythonSensitiveLoggingRule
from rules.python.swallowed_exception import PythonSwallowedExceptionRule
from rules.python.unsafe_error_response import PythonUnsafeErrorResponseRule


def default_rule_analyzers() -> tuple[RuleAnalyzer, ...]:
    return (
        PythonSensitiveLoggingRule(),
        PythonSwallowedExceptionRule(),
        PythonUnsafeErrorResponseRule(),
        JavaSensitiveLoggingRule(),
        JavaSwallowedExceptionRule(),
        JavaUnsafeErrorResponseRule(),
        JavaConsoleLoggingRule(),
    )


def analyzers_for_language(language: str) -> list[RuleAnalyzer]:
    return [
        analyzer
        for analyzer in default_rule_analyzers()
        if language in analyzer.languages
    ]
