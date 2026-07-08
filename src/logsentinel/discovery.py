from pathlib import Path

from logsentinel.config import Settings
from logsentinel.domain import CodeFile
from logsentinel.observability import get_logger
from logsentinel.preprocessor import RepoPreprocessor

logger = get_logger("discovery")


def discover_code_files(
    repo_path: Path,
    settings: Settings,
    max_files: int | None = None,
) -> tuple[list[CodeFile], list[str]]:
    logger.debug("Discovering code files through RepoPreprocessor")
    return RepoPreprocessor(settings).collect(repo_path, max_files=max_files)
