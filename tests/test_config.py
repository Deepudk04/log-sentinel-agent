import config


def test_load_settings_reads_dotenv(monkeypatch, tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("GEMINI_API_KEY=dotenv-key\nLOGSENTINEL_MAX_FILES=12\n", encoding="utf-8")
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path)
    monkeypatch.chdir(tmp_path)
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


def test_load_settings_reads_logsentinel_yml(monkeypatch, tmp_path):
    config_path = tmp_path / "logsentinel.yml"
    config_path.write_text(
        "\n".join(
            [
                "languages:",
                "  include: ['python']",
                "  exclude: ['java']",
                "paths:",
                "  ignore:",
                "    - '**/generated/**'",
                "limits:",
                "  max_file_size_kb: 7",
                "  max_files: 9",
                "  max_snippets_per_file: 3",
                "semantic:",
                "  enabled: false",
                "  min_confidence: 0.8",
                "  timeout_seconds: 11",
                "  cache_enabled: false",
                "reporting:",
                "  formats: ['markdown', 'json']",
                "  fail_on_severity: 'medium'",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(config, "PROJECT_ROOT", tmp_path)
    monkeypatch.delenv("LOGSENTINEL_MAX_FILES", raising=False)
    monkeypatch.delenv("LOGSENTINEL_MAX_FILE_BYTES", raising=False)

    settings = config.load_settings()

    assert settings.languages_include == ("python",)
    assert settings.languages_exclude == ("java",)
    assert settings.ignore_patterns == ("**/generated/**",)
    assert settings.max_file_bytes == 7 * 1024
    assert settings.max_files == 9
    assert settings.max_snippets_per_file == 3
    assert settings.semantic_enabled is False
    assert settings.semantic_min_confidence == 0.8
    assert settings.semantic_timeout_seconds == 11
    assert settings.semantic_cache_enabled is False
    assert settings.report_formats == ("markdown", "json")
    assert settings.fail_on_severity == "medium"
