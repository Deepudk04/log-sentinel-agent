from logsentinel import config


def test_load_settings_reads_dotenv(monkeypatch, tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("GEMINI_API_KEY=dotenv-key\nLOGSENTINEL_MAX_FILES=12\n", encoding="utf-8")
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("LOGSENTINEL_MAX_FILES", raising=False)

    settings = config.load_settings()

    assert settings.gemini_api_key == "dotenv-key"
    assert settings.max_files == 12


def test_load_settings_keeps_existing_environment(monkeypatch, tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("GEMINI_API_KEY=dotenv-key\n", encoding="utf-8")
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path)
    monkeypatch.setenv("GEMINI_API_KEY", "env-key")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    settings = config.load_settings()

    assert settings.gemini_api_key == "env-key"
