from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

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


def load_settings() -> Settings:
    _load_dotenv()
    settings = Settings(
        gemini_api_key=os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-3.5-flash"),
        output_dir=Path(os.getenv("LOGSENTINEL_OUTPUT_DIR", "reports")),
        max_file_bytes=_int_from_env("LOGSENTINEL_MAX_FILE_BYTES", 512 * 1024),
        max_files=_int_from_env("LOGSENTINEL_MAX_FILES", 500),
        max_snippets=_int_from_env("LOGSENTINEL_MAX_SNIPPETS", 40),
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
