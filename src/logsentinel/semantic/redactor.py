from __future__ import annotations

import re

SECRET_PATTERNS = (
    (
        re.compile(r"(?i)(password|passwd|pwd|secret)\s*[:=]\s*['\"]?[^'\"\s,;]+"),
        r"\1=[REDACTED_SECRET]",
    ),
    (
        re.compile(r"(?i)(api[_-]?key)\s*[:=]\s*['\"]?[^'\"\s,;]+"),
        r"\1=[REDACTED_SECRET]",
    ),
    (
        re.compile(r"(?i)(authorization)\s*[:=]\s*['\"]?[^'\"\r\n]+"),
        r"\1=[REDACTED_TOKEN]",
    ),
    (
        re.compile(r"(?i)(cookie|session[_-]?id)\s*[:=]\s*['\"]?[^'\"\s,;]+"),
        r"\1=[REDACTED_TOKEN]",
    ),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "[REDACTED_TOKEN]",
    ),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{12,}"), r"\1[REDACTED_TOKEN]"),
    (
        re.compile(
            r"(?i)(jdbc:[^'\"\s]+|postgres(?:ql)?://[^'\"\s]+|mysql://[^'\"\s]+|"
            r"mongodb(?:\+srv)?://[^'\"\s]+)"
        ),
        "[REDACTED_CONNECTION_STRING]",
    ),
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[REDACTED_SECRET]"),
)


class SecretRedactor:
    def redact(self, text: str) -> str:
        redacted = text
        for pattern, replacement in SECRET_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted
