from pathlib import Path

from logsentinel.deterministic import DeterministicAnalyzer
from logsentinel.domain import CodeFile
from logsentinel.rule_catalog import load_rules


def test_detects_sensitive_logging_in_python():
    code = CodeFile(
        path=Path("app.py"),
        relative_path="app.py",
        language="python",
        text='import logging\nlogging.info("password=%s", password)\n',
    )

    findings, _ = DeterministicAnalyzer(load_rules()).analyze([code])

    assert any(finding.rule_id == "LOG-003" for finding in findings)


def test_detects_swallowed_exception_in_python():
    code = CodeFile(
        path=Path("app.py"),
        relative_path="app.py",
        language="python",
        text="def f():\n    try:\n        risky()\n    except Exception:\n        pass\n",
    )

    findings, _ = DeterministicAnalyzer(load_rules()).analyze([code])

    assert any(finding.rule_id == "ERR-003" for finding in findings)


def test_detects_java_error_message_response():
    code = CodeFile(
        path=Path("AuthController.java"),
        relative_path="AuthController.java",
        language="java",
        text=(
            "class A { String f(Exception e) { "
            "return ResponseEntity.status(500).body(e.getMessage()); } }"
        ),
    )

    findings, _ = DeterministicAnalyzer(load_rules()).analyze([code])

    assert any(finding.rule_id == "ERR-002" for finding in findings)
