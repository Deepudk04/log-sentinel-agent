from pathlib import Path

from logsentinel.domain import CodeFile
from logsentinel.treesitter import TreeSitterService


class _Tree:
    root_node = object()


class _StrParser:
    def parse(self, source):
        if not isinstance(source, str):
            raise TypeError("source must be str")
        return _Tree()


class _BytesParser:
    def parse(self, source):
        if not isinstance(source, bytes):
            raise TypeError("source must be bytes")
        return _Tree()


def _code_file() -> CodeFile:
    return CodeFile(
        path=Path("app.py"),
        relative_path="app.py",
        language="python",
        text="print('ok')\n",
    )


def test_parse_supports_string_parser_api():
    service = TreeSitterService()
    service._parsers["python"] = _StrParser()

    parsed = service.parse(_code_file())

    assert parsed.parser_available is True
    assert parsed.error is None


def test_parse_falls_back_to_bytes_parser_api():
    service = TreeSitterService()
    service._parsers["python"] = _BytesParser()

    parsed = service.parse(_code_file())

    assert parsed.parser_available is True
    assert parsed.error is None
