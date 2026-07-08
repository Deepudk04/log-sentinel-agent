from __future__ import annotations

from logsentinel.rules.base import RuleAnalyzer
from logsentinel.rules.java.console_logging import JavaConsoleLoggingRule
from logsentinel.rules.java.sensitive_logging import JavaSensitiveLoggingRule
from logsentinel.rules.java.swallowed_exception import JavaSwallowedExceptionRule
from logsentinel.rules.java.unsafe_error_response import JavaUnsafeErrorResponseRule
from logsentinel.rules.python.sensitive_logging import PythonSensitiveLoggingRule
from logsentinel.rules.python.swallowed_exception import PythonSwallowedExceptionRule
from logsentinel.rules.python.unsafe_error_response import PythonUnsafeErrorResponseRule


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
