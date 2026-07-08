# LogSentinel

LogSentinel scans Python and Java repositories for logging and exception handling problems. It combines:

- deterministic checks over Tree-sitter syntax trees
- semantic checks over minimized snippets using Gemini
- a data-driven OWASP-backed rule catalog
- a simple FastAPI web UI
- Markdown reports

The first catalog contains 10 rules sourced from:

- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP Error Handling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html

## Requirements

- Python 3.11+
- A Gemini API key for semantic analysis
- Network access during dependency installation
- Optional network access on first Tree-sitter parser load if the language pack needs to populate its cache

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e ".[dev]"
```

If Python fails with an error like:

```text
No Python at '"C:\Users\...\Python312\python.exe'
```

the local virtual environment is pointing at a Python installation that no longer
exists. Install Python 3.11 or newer, remove the stale `.venv` directory, and run
the setup commands above again.

Set Gemini only when you want the semantic pass:

```powershell
$env:GEMINI_API_KEY = "your-key"
$env:GEMINI_MODEL = "gemini-3.5-flash"
```

To see detailed background progress, set the log level before starting the app:

```powershell
$env:LOGSENTINEL_LOG_LEVEL = "DEBUG"
```

Or add it to `.env`:

```env
LOGSENTINEL_LOG_LEVEL=DEBUG
```

`gemini-3.5-flash` is the default because Google currently lists it as the current stable Flash model in Gemini API docs. You can override it with `GEMINI_MODEL`.

## Run The Web UI

```powershell
logsentinel-web
```

Open:

```text
http://127.0.0.1:8000
```

## Run From CLI

```powershell
logsentinel-scan C:\path\to\repo --no-semantic
```

With Gemini:

```powershell
logsentinel-scan C:\path\to\repo
```

Reports are written to `reports/` by default.

## Configuration

LogSentinel loads `logsentinel.yml` from the current working directory when present. Start from:

```powershell
Copy-Item logsentinel.example.yml logsentinel.yml
```

Supported settings include language include/exclude lists, ignore patterns, file limits,
semantic settings, and reporting defaults.

Repository-specific ignores can also be added to `.logsentinelignore` using gitignore-style
glob patterns. LogSentinel also applies common build, vendor, cache, and generated-directory
skips by default.

## Rule Catalog

The catalog lives at:

```text
src/logsentinel/rules/owasp_logging_exception.json
```

Each rule includes:

- stable rule ID
- analyzer type: deterministic, semantic, or hybrid
- severity
- OWASP source URL and line references gathered during implementation
- deterministic signals where applicable
- semantic prompt text used by Gemini

Current rules:

- `LOG-001` Security-relevant events are logged
- `LOG-002` Log entries include investigation context
- `LOG-003` Sensitive data is excluded from logs
- `LOG-004` Untrusted event data is sanitized before logging
- `LOG-005` Application-wide logging mechanism is used
- `LOG-006` Logging failures do not break application flow or leak information
- `LOG-007` Required logging cannot be completely disabled
- `ERR-001` Unexpected errors return generic responses and are logged server-side
- `ERR-002` Technical error details are not exposed to callers
- `ERR-003` Caught exceptions are logged or propagated

## Architecture

```text
FastAPI UI / CLI
  -> LangGraph workflow
    -> file discovery
    -> deterministic Tree-sitter checks
    -> snippet minimization
    -> Gemini semantic checks
    -> Markdown report
```

Gemini receives only extracted snippets, not full files. Semantic findings are accepted only if the model returns a rule ID already present in the local catalog and a path that was included in the snippet payload.

## Development

```powershell
pytest
ruff check .
```

Sample vulnerable inputs are under `sample_repos/`.
