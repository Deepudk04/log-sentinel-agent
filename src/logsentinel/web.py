from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from logsentinel.agent import run_scan
from logsentinel.config import load_settings
from logsentinel.domain import ScanRequest

PACKAGE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="LogSentinel", version="0.1.0")
app.mount("/static", StaticFiles(directory=PACKAGE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=PACKAGE_DIR / "templates")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    settings = load_settings()
    return templates.TemplateResponse(
        request,
        "index.html",
        context={
            "repo_path": "",
            "use_semantic": bool(settings.gemini_api_key),
            "max_files": settings.max_files,
            "max_snippets": settings.max_snippets,
            "markdown_report": None,
            "findings_count": None,
            "report_filename": None,
            "notes": [],
            "error": None,
        },
    )


@app.post("/scan", response_class=HTMLResponse)
async def scan(
    request: Request,
    repo_path: str = Form(...),
    use_semantic: bool = Form(False),
    max_files: int = Form(500),
    max_snippets: int = Form(40),
):
    try:
        result = run_scan(
            ScanRequest(
                repo_path=Path(repo_path),
                use_semantic=use_semantic,
                max_files=max_files,
                max_snippets=max_snippets,
                write_report=True,
            )
        )
        report_filename = Path(result.report_path).name if result.report_path else None
        return templates.TemplateResponse(
            request,
            "index.html",
            context={
                "repo_path": repo_path,
                "use_semantic": use_semantic,
                "max_files": max_files,
                "max_snippets": max_snippets,
                "markdown_report": result.markdown_report,
                "findings_count": len(result.findings),
                "report_filename": report_filename,
                "notes": result.notes,
                "error": None,
            },
        )
    except Exception as exc:
        return templates.TemplateResponse(
            request,
            "index.html",
            context={
                "repo_path": repo_path,
                "use_semantic": use_semantic,
                "max_files": max_files,
                "max_snippets": max_snippets,
                "markdown_report": None,
                "findings_count": None,
                "report_filename": None,
                "notes": [],
                "error": str(exc),
            },
            status_code=400,
        )


@app.get("/reports/{filename}")
async def download_report(filename: str):
    if Path(filename).name != filename or not filename.endswith(".md"):
        return PlainTextResponse("Invalid report path.", status_code=400)
    settings = load_settings()
    path = (settings.output_dir / filename).resolve()
    if not path.exists():
        return PlainTextResponse("Report not found.", status_code=404)
    return FileResponse(path, media_type="text/markdown", filename=filename)


def main() -> None:
    import uvicorn

    uvicorn.run("logsentinel.web:app", host="127.0.0.1", port=8000, reload=True)
