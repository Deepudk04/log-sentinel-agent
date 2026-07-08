from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

from domain import Rule, rule_from_dict


@lru_cache(maxsize=1)
def load_rules() -> tuple[Rule, ...]:
    raw = (
        resources.files("rules")
        .joinpath("owasp_logging_exception.json")
        .read_text(encoding="utf-8")
    )
    payload = json.loads(raw)
    return tuple(rule_from_dict(item) for item in payload["rules"])


def rules_by_id() -> dict[str, Rule]:
    return {rule.id: rule for rule in load_rules()}
