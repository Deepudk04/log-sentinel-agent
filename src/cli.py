from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent import run_scan
from config import load_settings
from domain import ScanRequest
from observability import configure_logging, get_logger
from reporting import SEVERITY_ORDER, render_json_report, render_sarif

logger = get_logger("cli")


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    parser = argparse.ArgumentParser(description="Scan logging and exception handling issues.")
    parser.add_argument("repo_path", help="Repository or file path to scan.")
    parser.add_argument(
        "--no-semantic",
        action="store_true",
        help="Disable Gemini semantic analysis.",
    )
    parser.add_argument("--max-files", type=int, default=None)
    parser.add_argument("--max-snippets", type=int, default=None)
    parser.add_argument("--no-write-report", action="store_true")
    parser.add_argument(
        "--format",
        default=None,
        help="Comma-separated output formats: markdown,json,sarif.",
    )
    parser.add_argument("--fail-on", default=None, help="Fail on severity at or above this level.")
    parser.add_argument("--config", default=None, help="Path to logsentinel.yml.")
    args = parser.parse_args(argv)
    logger.info("CLI scan started for %s", args.repo_path)
    settings = load_settings(Path(args.config)) if args.config else load_settings()
    formats = _formats(args.format, settings.report_formats)
    fail_on = args.fail_on or settings.fail_on_severity

    result = run_scan(
        ScanRequest(
            repo_path=Path(args.repo_path),
            use_semantic=not args.no_semantic,
            max_files=args.max_files,
            max_snippets=args.max_snippets,
            write_report=not args.no_write_report,
            formats=formats,
            fail_on_severity=fail_on,  # type: ignore[arg-type]
        ),
        settings=settings,
    )
    logger.info("CLI scan finished with %s findings", len(result.findings))
    sys.stdout.write(_stdout_report(result, formats))
    if result.report_paths:
        sys.stderr.write(f"\nReports written: {result.report_paths}\n")
    return _exit_code(result.findings, fail_on)


def _formats(raw: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
    if not raw:
        return default
    return tuple(item.strip().lower() for item in raw.split(",") if item.strip())


def _stdout_report(result, formats: tuple[str, ...]) -> str:
    if len(formats) == 1 and formats[0] == "json":
        return render_json_report(result)
    if len(formats) == 1 and formats[0] == "sarif":
        return render_sarif(result)
    return result.markdown_report


def _exit_code(findings, fail_on: str | None) -> int:
    if not fail_on:
        return 0
    threshold = SEVERITY_ORDER.get(fail_on)
    if threshold is None:
        return 2
    return int(any(SEVERITY_ORDER[finding.severity] <= threshold for finding in findings))


if __name__ == "__main__":
    raise SystemExit(main())
