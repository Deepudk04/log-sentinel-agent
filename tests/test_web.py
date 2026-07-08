from fastapi.testclient import TestClient

import web as web
from web import app


def test_index_renders_html():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert "LogSentinel" in response.text


def test_scan_hides_raw_exception_details(monkeypatch):
    def fail_scan(*args, **kwargs):
        raise RuntimeError("raw secret failure")

    monkeypatch.setattr(web, "run_scan", fail_scan)

    response = TestClient(app).post(
        "/scan",
        data={"repo_path": ".", "max_files": "1", "max_snippets": "1"},
    )

    assert response.status_code == 400
    assert "raw secret failure" not in response.text
    assert "error_id=" in response.text
