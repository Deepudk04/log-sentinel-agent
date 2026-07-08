from pathlib import Path

from logsentinel.language import LanguageDetector


def test_language_detector_detects_supported_languages():
    detector = LanguageDetector()

    assert detector.detect(Path("app.py")) == "python"
    assert detector.detect(Path("AuthController.java")) == "java"
    assert detector.detect(Path("package.json")) is None


def test_language_detector_honors_include_and_exclude():
    detector = LanguageDetector(include=("python", "java"), exclude=("java",))

    assert detector.detect(Path("app.py")) == "python"
    assert detector.detect(Path("AuthController.java")) is None
