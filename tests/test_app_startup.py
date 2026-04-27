from fastapi.testclient import TestClient

from app.main import app


class _FailingSessionContext:
    async def __aenter__(self):
        raise RuntimeError("db down")

    async def __aexit__(self, exc_type, exc, tb):
        return False


def test_app_starts_without_database(monkeypatch):
    monkeypatch.setattr("app.main.get_session_factory", lambda: lambda: _FailingSessionContext())

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
