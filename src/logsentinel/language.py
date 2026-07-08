from __future__ import annotations

from pathlib import Path

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".java": "java",
}


class LanguageDetector:
    def __init__(
        self,
        include: tuple[str, ...] = ("python", "java"),
        exclude: tuple[str, ...] = (),
    ) -> None:
        self.include = set(include)
        self.exclude = set(exclude)

    def detect(self, path: Path) -> str | None:
        language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
        if language is None:
            return None
        if language not in self.include:
            return None
        if language in self.exclude:
            return None
        return language
