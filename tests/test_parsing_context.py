from pathlib import Path

from domain import CodeFile
from parsing.treesitter_service import TreeSitterService


class _NoParserService(TreeSitterService):
    def _get_parser(self, language: str):
        self._import_error = f"No parser for {language}"
        return None


def test_analyze_file_extracts_python_context_with_regex_fallback():
    code_file = CodeFile(
        path=Path("app.py"),
        relative_path="app.py",
        language="python",
        text=(
            "import logging\n"
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n\n"
            "@app.exception_handler(Exception)\n"
            "def handle_error(request, exc):\n"
            "    logging.error(str(exc))\n"
            "    return {'error': 'failed'}\n\n"
            "@app.get('/login')\n"
            "def login(request):\n"
            "    try:\n"
            "        risky()\n"
            "    except Exception:\n"
            "        print('failed')\n"
        ),
    )

    context = _NoParserService().analyze_file(code_file)

    assert context.parsed_tree.parser_available is False
    assert any(symbol.name == "login" for symbol in context.symbols)
    assert any(block.kind == "exception" for block in context.exception_blocks)
    assert any(call.kind == "logger" for call in context.logger_calls)
    assert any(call.kind == "console" for call in context.console_calls)
    assert any(block.kind == "api_handler" for block in context.api_handlers)
    assert any(
        block.kind == "global_exception_handler"
        for block in context.global_exception_handlers
    )
    assert "import logging" in context.imports


def test_analyze_file_extracts_java_context_with_regex_fallback():
    code_file = CodeFile(
        path=Path("AuthController.java"),
        relative_path="AuthController.java",
        language="java",
        text=(
            "import org.springframework.web.bind.annotation.GetMapping;\n"
            "class AuthController {\n"
            "  @GetMapping(\"/login\")\n"
            "  String login() {\n"
            "    try { risky(); }\n"
            "    catch (Exception e) { System.out.println(e.getMessage()); }\n"
            "  }\n"
            "}\n"
        ),
    )

    context = _NoParserService().analyze_file(code_file)

    assert any(symbol.name == "AuthController" for symbol in context.symbols)
    assert any(symbol.name == "login" for symbol in context.symbols)
    assert any(block.kind == "catch" for block in context.exception_blocks)
    assert any(call.kind == "console" for call in context.console_calls)
    assert any(block.kind == "api_handler" for block in context.api_handlers)
