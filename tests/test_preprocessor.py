from pathlib import Path

from logsentinel.config import Settings
from logsentinel.preprocessor import RepoPreprocessor


def _settings() -> Settings:
    return Settings(
        gemini_api_key=None,
        gemini_model="gemini-3.5-flash",
        output_dir=Path("reports"),
        max_file_bytes=1024,
        max_files=100,
        max_snippets=40,
        languages_include=("python", "java"),
        languages_exclude=(),
        ignore_patterns=(),
        max_snippets_per_file=20,
        semantic_enabled=True,
        semantic_provider="gemini",
        semantic_min_confidence=0.70,
        redact_before_llm=True,
        report_formats=("markdown",),
        fail_on_severity="high",
    )


def test_preprocessor_applies_logsentinelignore_and_hashes_files(tmp_path):
    (tmp_path / ".logsentinelignore").write_text("ignored.py\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "ignored.py").write_text("print('skip')\n", encoding="utf-8")

    files, skipped = RepoPreprocessor(_settings()).collect(tmp_path)

    assert [file.relative_path for file in files] == ["app.py"]
    assert files[0].file_hash
    assert skipped == []


def test_preprocessor_skips_binary_files(tmp_path):
    (tmp_path / "binary.py").write_bytes(b"\x00\x01\x02")

    files, skipped = RepoPreprocessor(_settings()).collect(tmp_path)

    assert files == []
    assert any("binary" in item for item in skipped)


def test_preprocessor_enforces_file_limit(tmp_path):
    (tmp_path / "a.py").write_text("print('a')\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("print('b')\n", encoding="utf-8")

    files, skipped = RepoPreprocessor(_settings()).collect(tmp_path, max_files=1)

    assert len(files) == 1
    assert any("File limit reached" in item for item in skipped)
