from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from logsentinel.observability import configure_logging, get_logger

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parents[1]
logger = get_logger("config")


def _load_dotenv() -> None:
    env_paths = [Path.cwd() / ".env", PROJECT_ROOT / ".env"]
    seen: set[Path] = set()
    for env_path in env_paths:
        env_path = env_path.resolve()
        if env_path in seen or not env_path.exists():
            logger.debug("No .env loaded from %s", env_path)
            continue
        seen.add(env_path)
        loaded = 0
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            name = name.strip()
            value = value.strip().strip("\"'")
            if name and name not in os.environ:
                os.environ[name] = value
                loaded += 1
        configure_logging()
        logger.info("Loaded %s settings from %s", loaded, env_path)


def _int_from_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    gemini_api_key: str | None
    gemini_model: str
    output_dir: Path
    max_file_bytes: int
    max_files: int
    max_snippets: int
    languages_include: tuple[str, ...]
    languages_exclude: tuple[str, ...]
    ignore_patterns: tuple[str, ...]
    max_snippets_per_file: int
    semantic_enabled: bool
    semantic_provider: str
    semantic_min_confidence: float
    redact_before_llm: bool
    report_formats: tuple[str, ...]
    fail_on_severity: str | None


def _load_yaml_config() -> dict[str, Any]:
    for config_path in (Path.cwd() / "logsentinel.yml", PROJECT_ROOT / "logsentinel.yml"):
        config_path = config_path.resolve()
        if not config_path.exists():
            logger.debug("No logsentinel.yml loaded from %s", config_path)
            continue
        try:
            import yaml
        except Exception as exc:
            raise RuntimeError("logsentinel.yml requires PyYAML to be installed") from exc
        logger.info("Loaded configuration from %s", config_path)
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"Configuration file must contain a YAML mapping: {config_path}")
        return raw
    return {}


def _nested(config: dict[str, Any], section: str, key: str, default: Any) -> Any:
    value = config.get(section, {})
    if not isinstance(value, dict):
        return default
    return value.get(key, default)


def _str_tuple(value: object, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return default


def _bool_from_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _float_from_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def load_settings() -> Settings:
    _load_dotenv()
    config = _load_yaml_config()
    max_file_size_kb = _nested(config, "limits", "max_file_size_kb", 500)
    max_file_bytes = int(max_file_size_kb) * 1024
    configured_formats = _str_tuple(_nested(config, "reporting", "formats", None), ("markdown",))
    settings = Settings(
        gemini_api_key=os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-3.5-flash"),
        output_dir=Path(os.getenv("LOGSENTINEL_OUTPUT_DIR", "reports")),
        max_file_bytes=_int_from_env("LOGSENTINEL_MAX_FILE_BYTES", max_file_bytes),
        max_files=_int_from_env("LOGSENTINEL_MAX_FILES", int(_nested(config, "limits", "max_files", 500))),
        max_snippets=_int_from_env("LOGSENTINEL_MAX_SNIPPETS", 40),
        languages_include=_str_tuple(_nested(config, "languages", "include", None), ("python", "java")),
        languages_exclude=_str_tuple(_nested(config, "languages", "exclude", None), ()),
        ignore_patterns=_str_tuple(_nested(config, "paths", "ignore", None), ()),
        max_snippets_per_file=int(_nested(config, "limits", "max_snippets_per_file", 20)),
        semantic_enabled=bool(_nested(config, "semantic", "enabled", True)),
        semantic_provider=str(_nested(config, "semantic", "provider", "gemini")),
        semantic_min_confidence=_float_from_env(
            "LOGSENTINEL_SEMANTIC_MIN_CONFIDENCE",
            float(_nested(config, "semantic", "min_confidence", 0.70)),
        ),
        redact_before_llm=_bool_from_env(
            "LOGSENTINEL_REDACT_BEFORE_LLM",
            bool(_nested(config, "semantic", "redact_before_llm", True)),
        ),
        report_formats=_str_tuple(os.getenv("LOGSENTINEL_REPORT_FORMATS"), configured_formats),
        fail_on_severity=os.getenv(
            "LOGSENTINEL_FAIL_ON_SEVERITY",
            _nested(config, "reporting", "fail_on_severity", None),
        ),
    )
    logger.debug(
        "Settings loaded: gemini_key_present=%s gemini_model=%s output_dir=%s "
        "max_file_bytes=%s max_files=%s max_snippets=%s",
        bool(settings.gemini_api_key),
        settings.gemini_model,
        settings.output_dir,
        settings.max_file_bytes,
        settings.max_files,
        settings.max_snippets,
    )
    return settings
