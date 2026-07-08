from __future__ import annotations

from datetime import UTC, datetime
from typing import TypedDict

from logsentinel.config import Settings, load_settings
from logsentinel.deterministic import DeterministicAnalyzer
from logsentinel.discovery import discover_code_files
from logsentinel.domain import CodeFile, Finding, Rule, ScanRequest, ScanResult, Snippet
from logsentinel.observability import get_logger
from logsentinel.reporting import render_markdown, write_report
from logsentinel.rule_catalog import load_rules
from logsentinel.semantic import GeminiSemanticAnalyzer
from logsentinel.snippets import SnippetCollector
from logsentinel.treesitter import TreeSitterService

logger = get_logger("agent")


class ScanState(TypedDict, total=False):
    request: ScanRequest
    settings: Settings
    generated_at: datetime
    rules: list[Rule]
    files: list[CodeFile]
    skipped: list[str]
    findings: list[Finding]
    snippets: list[Snippet]
    notes: list[str]
    markdown: str
    report_path: str | None


def run_scan(request: ScanRequest, settings: Settings | None = None) -> ScanResult:
    logger.info("Scan requested for %s", request.repo_path)
    active_settings = settings or load_settings()
    logger.debug(
        "Effective settings: semantic_key_present=%s model=%s output_dir=%s max_files=%s "
        "max_snippets=%s max_file_bytes=%s",
        bool(active_settings.gemini_api_key),
        active_settings.gemini_model,
        active_settings.output_dir,
        active_settings.max_files,
        active_settings.max_snippets,
        active_settings.max_file_bytes,
    )
    initial: ScanState = {
        "request": request,
        "settings": active_settings,
        "generated_at": datetime.now(UTC),
        "rules": list(load_rules()),
        "findings": [],
        "skipped": [],
        "snippets": [],
        "notes": [],
    }

    try:
        logger.debug("Building LangGraph workflow")
        graph = _build_graph()
        logger.info("Starting LangGraph scan workflow")
        final_state = graph.invoke(initial)
    except Exception as exc:
        logger.warning("LangGraph workflow failed; using direct pipeline: %s", exc)
        initial["notes"] = [
            *initial.get("notes", []),
            f"LangGraph execution unavailable; direct pipeline used instead ({exc}).",
        ]
        final_state = _run_direct(initial)

    result = _state_to_result(final_state)
    logger.info(
        "Scan complete: files=%s findings=%s snippets=%s skipped=%s report=%s",
        result.scanned_files,
        len(result.findings),
        result.snippets_sent,
        len(result.skipped),
        result.report_path or "not written",
    )
    return result


def _build_graph():
    from langgraph.graph import END, START, StateGraph

    builder = StateGraph(ScanState)
    builder.add_node("discover", _discover_node)
    builder.add_node("deterministic", _deterministic_node)
    builder.add_node("snippets", _snippet_node)
    builder.add_node("semantic", _semantic_node)
    builder.add_node("report", _report_node)

    builder.add_edge(START, "discover")
    builder.add_edge("discover", "deterministic")
    builder.add_edge("deterministic", "snippets")
    builder.add_edge("snippets", "semantic")
    builder.add_edge("semantic", "report")
    builder.add_edge("report", END)
    return builder.compile()


def _run_direct(state: ScanState) -> ScanState:
    for node in (_discover_node, _deterministic_node, _snippet_node, _semantic_node, _report_node):
        logger.debug("Running direct pipeline node: %s", node.__name__)
        state.update(node(state))
    return state


def _discover_node(state: ScanState) -> ScanState:
    request = state["request"]
    settings = state["settings"]
    notes = [*state.get("notes", [])]
    logger.info("Discovering code files under %s", request.repo_path)
    files, skipped = discover_code_files(request.repo_path, settings, request.max_files)
    logger.info("Discovery complete: supported_files=%s skipped=%s", len(files), len(skipped))
    if not files:
        logger.warning("No supported Python or Java files were found")
        notes.append("No supported Python or Java files were found.")
    return {"files": files, "skipped": skipped, "notes": notes}


def _deterministic_node(state: ScanState) -> ScanState:
    logger.info("Running deterministic analysis on %s files", len(state.get("files", [])))
    tree_sitter = TreeSitterService()
    analyzer = DeterministicAnalyzer(state["rules"], tree_sitter=tree_sitter)
    findings, notes = analyzer.analyze(state.get("files", []))
    deduped = _dedupe_findings(findings)
    logger.info(
        "Deterministic analysis complete: findings=%s notes=%s",
        len(deduped),
        len(notes),
    )
    return {"findings": deduped, "notes": [*state.get("notes", []), *notes]}


def _snippet_node(state: ScanState) -> ScanState:
    request = state["request"]
    settings = state["settings"]
    max_snippets = request.max_snippets or settings.max_snippets
    logger.info("Collecting semantic snippets with limit=%s", max_snippets)
    collector = SnippetCollector()
    snippets = collector.collect(
        state.get("files", []),
        state.get("findings", []),
        max_snippets=max_snippets,
    )
    logger.info("Snippet collection complete: snippets=%s", len(snippets))
    return {"snippets": snippets}


def _semantic_node(state: ScanState) -> ScanState:
    request = state["request"]
    settings = state["settings"]
    notes = [*state.get("notes", [])]
    findings = [*state.get("findings", [])]
    if not request.use_semantic or not settings.semantic_enabled:
        logger.info("Semantic analysis disabled for this scan")
        notes.append("Semantic analysis disabled for this scan.")
        return {"findings": findings, "notes": notes}

    logger.info("Running semantic analysis on %s snippets", len(state.get("snippets", [])))
    semantic = GeminiSemanticAnalyzer(state["settings"], state["rules"])
    result = semantic.analyze(state.get("snippets", []))
    findings.extend(result.findings)
    notes.extend(result.notes)
    deduped = _dedupe_findings(findings)
    logger.info(
        "Semantic analysis complete: semantic_findings=%s total_findings=%s notes=%s",
        len(result.findings),
        len(deduped),
        len(result.notes),
    )
    return {"findings": deduped, "notes": notes}


def _report_node(state: ScanState) -> ScanState:
    request = state["request"]
    settings = state["settings"]
    logger.info("Rendering Markdown report")
    result = _state_to_result({**state, "markdown": "", "report_path": None})
    markdown = render_markdown(result)
    report_path = None
    if request.write_report:
        report_path = str(write_report(markdown, settings.output_dir))
        logger.info("Report written to %s", report_path)
    else:
        logger.info("Report writing disabled")
    return {"markdown": markdown, "report_path": report_path}


def _state_to_result(state: ScanState) -> ScanResult:
    return ScanResult(
        repository=str(state["request"].repo_path.expanduser().resolve()),
        generated_at=state.get("generated_at") or datetime.now(UTC),
        scanned_files=len(state.get("files", [])),
        skipped=state.get("skipped", []),
        findings=state.get("findings", []),
        snippets_sent=len(state.get("snippets", [])),
        rules=state.get("rules", []),
        notes=state.get("notes", []),
        markdown_report=state.get("markdown", ""),
        report_path=state.get("report_path"),
    )


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, str, str]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = (
            finding.rule_id,
            finding.path,
            finding.line,
            finding.message,
            finding.analyzer,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
