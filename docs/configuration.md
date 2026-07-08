# Configuration

LogSentinel loads `logsentinel.yml` when present, or a path passed with `--config`.

```yaml
languages:
  include: ["python", "java"]
  exclude: []

paths:
  ignore:
    - "**/.venv/**"
    - "**/node_modules/**"
    - "**/target/**"
    - "**/build/**"
    - "**/dist/**"
    - "**/generated/**"

limits:
  max_file_size_kb: 500
  max_files: 5000
  max_snippets_per_file: 20

semantic:
  enabled: true
  provider: "gemini"
  min_confidence: 0.70
  redact_before_llm: true
  timeout_seconds: 30
  cache_enabled: true

reporting:
  formats: ["markdown", "json", "sarif", "html"]
  fail_on_severity: "high"
```

Use `.logsentinelignore` for repository-specific ignores. Patterns follow gitignore-style glob matching and are applied during preprocessing alongside default build, vendor, cache, generated, binary, minified, and size filters.

Semantic timeout and cache settings can also be overridden with `LOGSENTINEL_SEMANTIC_TIMEOUT_SECONDS` and `LOGSENTINEL_SEMANTIC_CACHE_ENABLED`.
