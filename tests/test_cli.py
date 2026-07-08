from cli import _exit_code, _formats
from domain import Finding
from rule_catalog import load_rules


def test_cli_formats_parse_comma_separated_values():
    assert _formats("markdown,json,sarif", ("markdown",)) == ("markdown", "json", "sarif")
    assert _formats(None, ("markdown",)) == ("markdown",)


def test_cli_exit_code_honors_fail_threshold():
    rule = next(rule for rule in load_rules() if rule.severity == "high")
    finding = Finding(
        rule_id=rule.id,
        rule_title=rule.title,
        severity=rule.severity,
        category=rule.category,
        analyzer="deterministic",
        path="app.py",
        line=1,
        message="Problem.",
        evidence="evidence",
        recommendation=rule.recommendation,
        confidence=0.9,
        source_refs=rule.source_refs,
    )

    assert _exit_code([finding], "high") == 1
    assert _exit_code([finding], "critical") == 0
    assert _exit_code([finding], "bogus") == 2
