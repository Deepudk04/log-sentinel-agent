from __future__ import annotations

import fnmatch
import hashlib
import os
from pathlib import Path

from logsentinel.config import Settings
from logsentinel.domain import CodeFile
from logsentinel.language import LanguageDetector
from logsentinel.observability import get_logger

logger = get_logger("preprocessor")

DEFAULT_IGNORE_PATTERNS = (
    ".git/**",
    "**/.git/**",
    ".hg/**",
    "**/.hg/**",
    ".svn/**",
    "**/.svn/**",
    ".venv/**",
    "**/.venv/**",
    "venv/**",
    "**/venv/**",
    "env/**",
    "**/env/**",
    "__pycache__/**",
    "**/__pycache__/**",
    ".mypy_cache/**",
    "**/.mypy_cache/**",
    ".pytest_cache/**",
    "**/.pytest_cache/**",
    ".ruff_cache/**",
    "**/.ruff_cache/**",
    "node_modules/**",
    "**/node_modules/**",
    "target/**",
    "**/target/**",
    "build/**",
    "**/build/**",
    "dist/**",
    "**/dist/**",
    ".idea/**",
    "**/.idea/**",
    ".vscode/**",
    "**/.vscode/**",
    "generated/**",
    "**/generated/**",
    "vendor/**",
    "**/vendor/**",
)


class RepoPreprocessor:
    def __init__(
        self,
        settings: Settings,
        language_detector: LanguageDetector | None = None,
    ) -> None:
        self.settings = settings
        self.language_detector = language_detector or LanguageDetector(
            include=settings.languages_include,
            exclude=settings.languages_exclude,
        )

    def collect(
        self,
        repo_path: Path,
        max_files: int | None = None,
        scan_mode: str = "full",
    ) -> tuple[list[CodeFile], list[str]]:
        if scan_mode != "full":
            raise ValueError(f"Unsupported scan mode: {scan_mode}")

        root = repo_path.expanduser().resolve()
        self._validate_root(root)
        limit = max_files or self.settings.max_files
        ignore_patterns = self._load_ignore_patterns(root)
        files: list[CodeFile] = []
        skipped: list[str] = []

        candidates = [root] if root.is_file() else self._walk_files(root, ignore_patterns)
        for path in candidates:
            resolved = path.resolve()
            if not self._is_within_root(resolved, root if root.is_dir() else root.parent):
                skipped.append(f"{path}: skipped because it resolves outside the scan root")
                logger.warning("Skipping path outside scan root: %s", path)
                continue

            relative = self._relative_path(resolved, root)
            if self._ignored(relative, ignore_patterns):
                logger.debug("Ignoring path by pattern: %s", relative)
                continue

            language = self.language_detector.detect(resolved)
            if language is None:
                logger.debug("Skipping unsupported language: %s", relative)
                continue

            if len(files) >= limit:
                skipped.append(
                    f"File limit reached at {limit}; remaining supported files were skipped."
                )
                logger.warning("File limit reached at %s", limit)
                break

            code_file = self._read_code_file(resolved, relative, language, skipped)
            if code_file is not None:
                files.append(code_file)

        logger.info("Preprocessing complete: files=%s skipped=%s", len(files), len(skipped))
        return files, skipped

    def _validate_root(self, root: Path) -> None:
        if not root.exists():
            logger.error("Repository path does not exist: %s", root)
            raise ValueError(f"Repository path does not exist: {root}")
        if root.is_symlink():
            target = root.resolve()
            if not self._is_within_root(target, root.parent.resolve()):
                raise ValueError(f"Repository path symlink resolves outside its parent: {root}")

    def _load_ignore_patterns(self, root: Path) -> tuple[str, ...]:
        patterns = [*DEFAULT_IGNORE_PATTERNS, *self.settings.ignore_patterns]
        base = root if root.is_dir() else root.parent
        for ignore_name in (".gitignore", ".logsentinelignore"):
            ignore_file = base / ignore_name
            if not ignore_file.exists():
                continue
            loaded = _read_ignore_file(ignore_file)
            patterns.extend(loaded)
            logger.info("Loaded %s ignore patterns from %s", len(loaded), ignore_file)
        return tuple(patterns)

    def _walk_files(self, root: Path, ignore_patterns: tuple[str, ...]):
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            base = Path(dirpath)
            kept_dirs = []
            for dirname in dirnames:
                rel = self._relative_path(base / dirname, root)
                if self._ignored(rel + "/", ignore_patterns):
                    logger.debug("Skipping ignored directory: %s", rel)
                    continue
                kept_dirs.append(dirname)
            dirnames[:] = kept_dirs
            for filename in filenames:
                yield base / filename

    def _read_code_file(
        self,
        path: Path,
        relative: str,
        language: str,
        skipped: list[str],
    ) -> CodeFile | None:
        try:
            content = path.read_bytes()
        except OSError as exc:
            skipped.append(f"{path}: unable to read file ({exc})")
            logger.warning("Unable to read file %s: %s", path, exc)
            return None

        if len(content) > self.settings.max_file_bytes:
            skipped.append(
                f"{path}: skipped because size exceeds {self.settings.max_file_bytes} bytes"
            )
            logger.warning("Skipping oversized file %s", path)
            return None
        if _is_binary(content):
            skipped.append(f"{path}: skipped because it appears to be binary")
            logger.debug("Skipping binary file: %s", path)
            return None
        if _is_minified(content):
            skipped.append(f"{path}: skipped because it appears to be minified")
            logger.debug("Skipping minified file: %s", path)
            return None

        text = content.decode("utf-8", errors="replace")
        file_hash = hashlib.sha256(content).hexdigest()
        logger.debug("Accepted file: %s language=%s sha256=%s", relative, language, file_hash)
        return CodeFile(
            path=path,
            relative_path=relative,
            language=language,
            text=text,
            file_hash=file_hash,
        )

    @staticmethod
    def _relative_path(path: Path, root: Path) -> str:
        base = root if root.is_dir() else root.parent
        try:
            return path.resolve().relative_to(base.resolve()).as_posix()
        except ValueError:
            return path.name

    @staticmethod
    def _is_within_root(path: Path, root: Path) -> bool:
        try:
            path.resolve().relative_to(root.resolve())
            return True
        except ValueError:
            return False

    @staticmethod
    def _ignored(relative_path: str, patterns: tuple[str, ...]) -> bool:
        normalized = relative_path.replace("\\", "/")
        for pattern in patterns:
            pattern = pattern.replace("\\", "/").strip()
            if not pattern:
                continue
            if pattern.endswith("/") and normalized.startswith(pattern.rstrip("/") + "/"):
                return True
            if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch("/" + normalized, pattern):
                return True
            if "/" not in pattern and fnmatch.fnmatch(Path(normalized).name, pattern):
                return True
        return False


def _read_ignore_file(path: Path) -> list[str]:
    patterns: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        patterns.append(stripped)
    return patterns


def _is_binary(content: bytes) -> bool:
    return b"\0" in content[:4096]


def _is_minified(content: bytes) -> bool:
    if len(content) < 20_000:
        return False
    sample = content[:20_000]
    lines = sample.splitlines() or [sample]
    longest_line = max(len(line) for line in lines)
    return longest_line > 1000
