# Security And Privacy

LogSentinel is designed for local and CI use. The scanner focuses on logging and exception-handling issues and avoids sending full source files to semantic providers.

Privacy controls:

- Gemini receives minimized snippets only, not whole repositories.
- Secrets are redacted before semantic analysis when `redact_before_llm=true`.
- Reports redact sensitive-looking evidence before writing Markdown, JSON, or SARIF.
- Semantic responses are untrusted candidate findings until local validation accepts them.
- Invalid JSON, invented rules, invented paths, invalid lines, missing evidence, and low confidence are rejected.

Web UI guidance:

- The FastAPI UI is intended for localhost.
- Do not expose it publicly without authentication and path sandboxing.
- Runtime exceptions are logged server-side with an `error_id`; the UI shows a generic failure message.
