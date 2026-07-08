from __future__ import annotations

import argparse
import sys
from pathlib import Path

from logsentinel.agent import run_scan
from logsentinel.domain import ScanRequest
from logsentinel.observability import configure_logging, get_logger

logger = get_logger("cli")


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    parser = argparse.ArgumentParser(description="Scan logging and exception handling issues.")
    parser.add_argument("repo_path", help="Repository or file path to scan.")
    parser.add_argument("--no-semantic", action="store_true", help="Disable Gemini semantic analysis.")
    parser.add_argument("--max-files", type=int, default=None)
    parser.add_argument("--max-snippets", type=int, default=None)
    parser.add_argument("--no-write-report", action="store_true")
    args = parser.parse_args(argv)
    logger.info("CLI scan started for %s", args.repo_path)

    result = run_scan(
        ScanRequest(
            repo_path=Path(args.repo_path),
            use_semantic=not args.no_semantic,
            max_files=args.max_files,
            max_snippets=args.max_snippets,
            write_report=not args.no_write_report,
        )
    )
    logger.info("CLI scan finished with %s findings", len(result.findings))
    sys.stdout.write(result.markdown_report)
    if result.report_path:
        sys.stderr.write(f"\nReport written to {result.report_path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
