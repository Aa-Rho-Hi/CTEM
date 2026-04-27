import asyncio
from types import SimpleNamespace

from app.services.itsm import ITSMService


class DummyResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class DummyClient:
    def __init__(self, recorder):
        self.recorder = recorder

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def post(self, url, headers=None, json=None):
        self.recorder.append({"url": url, "headers": headers, "json": json})
        if "servicenow" in url:
            return DummyResponse({"result": {"sys_id": "snow-1", "number": "INC0000001"}})
        return DummyResponse({"id": "jira-1", "key": "SEC-1", "self": "http://jira.local/SEC-1"})


def test_servicenow_ticket_populates_assignee(monkeypatch):
    calls = []
    monkeypatch.setattr("app.services.itsm.httpx.AsyncClient", lambda *args, **kwargs: DummyClient(calls))

    service = ITSMService()
    service.settings.servicenow_url = "https://servicenow.local"
    service.settings.servicenow_user = "user"
    service.settings.servicenow_pass = "pass"

    finding = SimpleNamespace(cve_id="CVE-2026-0001", asset_id="asset-1", severity="High", risk_score=88, id="finding-1")
    remediation = SimpleNamespace(risk_narrative="risk")

    asyncio.run(service._create_servicenow(finding, remediation, {"assignee": "sec.ops", "assignment_group": "Blue Team"}))

    assert calls[0]["json"]["assigned_to"] == "sec.ops"
    assert calls[0]["json"]["assignment_group"] == "Blue Team"


def test_jira_ticket_populates_assignee(monkeypatch):
    calls = []
    monkeypatch.setattr("app.services.itsm.httpx.AsyncClient", lambda *args, **kwargs: DummyClient(calls))

    service = ITSMService()
    service.settings.jira_url = "https://jira.local"
    service.settings.jira_api_key = "token"

    finding = SimpleNamespace(cve_id="CVE-2026-0001", asset_id="asset-1", severity="High", risk_score=88, id="finding-1")
    remediation = SimpleNamespace(risk_narrative="risk")

    asyncio.run(service._create_jira(finding, remediation, {"assignee": {"id": "acct-1"}, "project_key": "APPSEC"}))

    assert calls[0]["json"]["fields"]["assignee"] == {"id": "acct-1"}
    assert calls[0]["json"]["fields"]["project"]["key"] == "APPSEC"
