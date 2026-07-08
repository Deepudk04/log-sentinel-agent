from __future__ import annotations

import os
from pathlib import Path

from logsentinel.config import Settings
from logsentinel.domain import CodeFile
from logsentinel.observability import get_logger

logger = get_logger("discovery")

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".java": "java",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    "target",
    "build",
    "dist",
    ".idea",
    ".vscode",
}


def discover_code_files(
    repo_path: Path,
    settings: Settings,
    max_files: int | None = None,
) -> tuple[list[CodeFile], list[str]]:
    root = repo_path.expanduser().resolve()
    logger.debug("Resolved scan root: %s", root)
    if not root.exists():
        logger.error("Repository path does not exist: %s", root)
        raise ValueError(f"Repository path does not exist: {root}")

    limit = max_files or settings.max_files
    logger.debug("Discovery limits: max_files=%s max_file_bytes=%s", limit, settings.max_file_bytes)
    skipped: list[str] = []
    files: list[CodeFile] = []

    candidates = [root] if root.is_file() else _walk_files(root)
    for path in candidates:
        language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
        if not language:
            logger.debug("Skipping unsupported file type: %s", path)
            continue
        if len(files) >= limit:
            logger.warning("File limit reached at %s", limit)
            skipped.append(f"File limit reached at {limit}; remaining supported files were skipped.")
            break
        try:
            stat = path.stat()
        except OSError as exc:
            logger.warning("Unable to stat file %s: %s", path, exc)
            skipped.append(f"{path}: unable to stat file ({exc})")
            continue
        if stat.st_size > settings.max_file_bytes:
            logger.warning(
                "Skipping oversized file %s: size=%s limit=%s",
                path,
                stat.st_size,
                settings.max_file_bytes,
            )
            skipped.append(f"{path}: skipped because size exceeds {settings.max_file_bytes} bytes")
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Unable to read file %s: %s", path, exc)
            skipped.append(f"{path}: unable to read file ({exc})")
            continue
        try:
            relative = path.relative_to(root if root.is_dir() else root.parent).as_posix()
        except ValueError:
            relative = path.name
        files.append(CodeFile(path=path, relative_path=relative, language=language, text=text))
        logger.debug("Discovered %s file: %s", language, relative)

    return files, skipped


def _walk_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        original_dirnames = list(dirnames)
        dirnames[:] = [
            name
            for name in dirnames
            if name not in SKIP_DIRS and not name.startswith(".logsentinel")
        ]
        for skipped_dir in sorted(set(original_dirnames) - set(dirnames)):
            logger.debug("Skipping directory: %s", Path(dirpath) / skipped_dir)
        base = Path(dirpath)
        for filename in filenames:
            yield base / filename
