from dataclasses import dataclass
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.api import cli
from app.main import app

client = TestClient(app)
PAYLOAD = {
    "repository_name": "repo",
    "repository_full_name": "owner/repo",
    "clone_url": "https://github.com/owner/repo.git",
    "default_branch": "main",
    "branch": "feature/test",
    "before_commit": "a" * 40,
    "after_commit": "b" * 40,
    "sender": "developer",
}


def test_cli_authentication_required(monkeypatch):
    monkeypatch.setattr(cli, "CLI_API_TOKEN", "secret-token")
    response = client.post("/api/v1/cli/push-analysis", json=PAYLOAD)
    assert response.status_code == 401


def test_cli_valid_request_executes_agent_and_persists(monkeypatch):
    monkeypatch.setattr(cli, "CLI_API_TOKEN", "secret-token")
    calls = []
    monkeypatch.setattr(cli, "save_event", lambda **kwargs: SimpleNamespace(id=12))
    monkeypatch.setattr(cli, "save_analysis", lambda **kwargs: calls.append(("analysis", kwargs)))
    monkeypatch.setattr(cli, "mark_event_processed", lambda **kwargs: calls.append(("processed", kwargs)))

    class Agent:
        async def execute(self, event):
            calls.append(("execute", event))
            return SimpleNamespace(summary="ok", findings=["f"], recommendations=["r"], risk_level="LOW", model="test")

    monkeypatch.setattr(cli, "push_agent", Agent())
    response = client.post("/api/v1/cli/push-analysis", json=PAYLOAD, headers={"Authorization": "Bearer secret-token"})
    assert response.status_code == 200
    assert response.json() == {"status": "success", "analysis": {"summary": "ok", "findings": ["f"], "recommendations": ["r"], "risk_level": "LOW", "model": "test"}}
    assert [call[0] for call in calls] == ["execute", "analysis", "processed"]
    assert calls[0][1].after_commit == PAYLOAD["after_commit"]


def test_cli_rejects_invalid_request(monkeypatch):
    monkeypatch.setattr(cli, "CLI_API_TOKEN", "secret-token")
    response = client.post("/api/v1/cli/push-analysis", json={**PAYLOAD, "after_commit": "bad"}, headers={"Authorization": "Bearer secret-token"})
    assert response.status_code == 422
