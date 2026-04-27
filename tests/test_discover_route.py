from types import SimpleNamespace

import pytest

from app.routes import discover


class Recorder:
    def __init__(self):
        self.calls = []

    def send_task(self, name, args=None, kwargs=None):
        self.calls.append({"name": name, "args": args, "kwargs": kwargs})


@pytest.mark.asyncio
async def test_refresh_external_discovery_queues_mock_inputs_in_development(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(discover, "celery_app", recorder)
    monkeypatch.setattr(discover, "get_settings", lambda: SimpleNamespace(environment="development"))

    response = await discover.refresh_external_discovery(
        session=SimpleNamespace(info={"tenant_id": "tenant-1"})
    )

    assert response.message == "queued"
    assert len(recorder.calls) == 1
    call = recorder.calls[0]
    assert call["name"] == "app.tasks.scan_pipeline.discover_external_attack_surface"
    assert call["args"][0] == "tenant-1"
    assert call["args"][1]["certificate_transparency_results"]
    assert call["args"][1]["enumeration_results"]
    assert call["args"][1]["cloud_resources"]


def test_external_discovery_options_empty_outside_development(monkeypatch):
    monkeypatch.setattr(discover, "get_settings", lambda: SimpleNamespace(environment="production"))

    assert discover._external_discovery_options() == {}
