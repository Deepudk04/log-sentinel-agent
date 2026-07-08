# Rule Authoring

Rules live under `src/rules/` and implement the `RuleAnalyzer` protocol.

```python
class RuleAnalyzer(Protocol):
    rule_id: str
    languages: set[str]

    def analyze(self, context: FileAnalysisContext) -> list[FindingCandidate]:
        ...
```

Rules should return `FindingCandidate` objects, not final findings. Final severity, recommendation, and source references are normalized from the local OWASP-backed rule catalog before reporting.

Rule authoring guidelines:

- Keep the scope limited to logging and exception-handling behavior.
- Prefer parser context over raw regex matching when Tree-sitter data is available.
- Include concrete evidence that can be redacted and shown in reports.
- Use stable rule IDs from the catalog.
- Avoid creating findings that depend on semantic interpretation unless the rule is marked semantic or hybrid.
