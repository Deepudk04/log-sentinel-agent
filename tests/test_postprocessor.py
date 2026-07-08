from pathlib import Path

from core.postprocessor import PostProcessor
from domain import CodeFile, Finding
from rule_catalog import load_rules


def test_postprocessor_applies_suppressions_and_fingerprints():
    rule = next(rule for rule in load_rules() if rule.id == "LOG-003")
    code_file = CodeFile(
        path=Path("app.py"),
        relative_path="app.py",
        language="python",
        text="# logsentinel-disable-next-line LOG-003\nlogging.info('password')\n",
    )
    finding = Finding(
        rule_id=rule.id,
        rule_title=rule.title,
        severity=rule.severity,
        category=rule.category,
        analyzer="deterministic",
        path="app.py",
        line=2,
        message="Sensitive logging.",
        evidence="password",
        recommendation=rule.recommendation,
        confidence=0.9,
        source_refs=rule.source_refs,
    )

    processed = PostProcessor().process([finding], [code_file])

    assert processed == []


def test_postprocessor_dedupes_and_adds_fingerprint():
    rule = next(rule for rule in load_rules() if rule.id == "LOG-003")
    finding = Finding(
        rule_id=rule.id,
        rule_title=rule.title,
        severity=rule.severity,
        category=rule.category,
        analyzer="deterministic",
        path="app.py",
        line=2,
        message="Sensitive logging.",
        evidence="password",
        recommendation=rule.recommendation,
        confidence=0.9,
        source_refs=rule.source_refs,
    )

    processed = PostProcessor().process([finding, finding], [])

    assert len(processed) == 1
    assert processed[0].fingerprint
