# Architecture

LogSentinel scans Python and Java repositories with a deterministic-first pipeline. Tree-sitter parsing and rule plugins produce local findings. Optional Gemini review receives only minimized, redacted snippets and returns candidate findings that must pass deterministic validation before they appear in reports.

```mermaid
flowchart TD
    A[CLI / Web UI / GitHub Action] --> B[Scan Request Validator]
    B --> C[Repo Discovery and Preprocessing]
    C --> D[Language Detection and File Filtering]
    D --> E[Tree-sitter Parser]
    E --> F[Deterministic Rule Engine]
    F --> G[Snippet Builder]
    G --> H[Secret Redactor]
    H --> I[Gemini Semantic Analyzer]
    I --> J[Semantic Finding Validator]
    J --> K[Finding PostProcessor]
    K --> L[Markdown / JSON / SARIF Reports]
    L --> M[Exit Code / CI Gate]
```

The core trust boundary is between Gemini output and accepted findings. Semantic output is treated as untrusted data until `SemanticFindingValidator` confirms rule IDs, paths, line ranges, evidence, confidence, and catalog alignment.
