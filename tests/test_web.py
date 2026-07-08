from fastapi.testclient import TestClient

from logsentinel.web import app


def test_index_renders_html():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert "LogSentinel" in response.text
