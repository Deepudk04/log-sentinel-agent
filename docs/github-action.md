# GitHub Action

The repository includes a composite action in `action.yml`.

Example:

```yaml
name: LogSentinel

on:
  pull_request:
  push:

jobs:
  logsentinel:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: Deepudk04/log-sentinel-agent@v1
        with:
          path: "."
          semantic_enabled: "false"
          fail_on: "high"
          output_format: "sarif"
          upload_sarif: "true"
```

Inputs:

- `path`: repository path to scan.
- `config`: optional `logsentinel.yml` path.
- `semantic_enabled`: set to `"true"` to enable Gemini.
- `gemini_api_key`: API key for semantic analysis.
- `fail_on`: severity gate for CI.
- `output_format`: comma-separated output formats.
- `upload_sarif`: upload generated SARIF to GitHub code scanning.
