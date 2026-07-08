from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from domain import ScanResult
from reporting.html import render_html_report
from reporting.json_report import render_json_report
from reporting.markdown import render_markdown
from reporting.sarif import render_sarif


def write_report(markdown: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    path = output_dir / f"logsentinel-{timestamp}.md"
    path.write_text(markdown, encoding="utf-8")
    return path


def write_reports(result: ScanResult, output_dir: Path, formats: tuple[str, ...]) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    rendered = {
        "markdown": result.markdown_report or render_markdown(result),
        "json": render_json_report(result),
        "sarif": render_sarif(result),
        "html": render_html_report(result),
    }
    extensions = {"markdown": "md", "json": "json", "sarif": "sarif", "html": "html"}
    paths: dict[str, str] = {}
    for report_format in formats:
        normalized = report_format.strip().lower()
        if normalized not in rendered:
            continue
        path = output_dir / f"logsentinel-{timestamp}.{extensions[normalized]}"
        path.write_text(rendered[normalized], encoding="utf-8")
        paths[normalized] = str(path)
    return paths
