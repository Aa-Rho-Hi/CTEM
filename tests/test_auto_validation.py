import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.services.validation_service import ValidationService


class FakeSession:
    def __init__(self, finding):
        self._finding = finding
        self.added = []

    async def get(self, model, key):
        return self._finding

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        pass


class NoopAuditWriter:
    async def write(self, *args, **kwargs):
        pass


def _patch_aw(monkeypatch):
    import app.services.validation_service as vs_module
    monkeypatch.setattr(vs_module, "AuditWriter", lambda: NoopAuditWriter())


def _finding(**kwargs):
    defaults = dict(
        id=uuid4(),
        epss_score=0.1,
        is_kev=False,
        exploit_db_id=None,
        matched_campaign_id=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_epss_triggers(monkeypatch):
    _patch_aw(monkeypatch)
    finding = _finding(epss_score=0.8)
    result = asyncio.run(ValidationService().auto_validate(FakeSession(finding), str(finding.id), "t1"))
    assert result["auto_validated"] is True
    assert "epss_probability" in result["signals"]


def test_kev_triggers(monkeypatch):
    _patch_aw(monkeypatch)
    finding = _finding(is_kev=True)
    result = asyncio.run(ValidationService().auto_validate(FakeSession(finding), str(finding.id), "t1"))
    assert result["auto_validated"] is True
    assert "cisa_kev" in result["signals"]


def test_no_signals(monkeypatch):
    _patch_aw(monkeypatch)
    finding = _finding()
    result = asyncio.run(ValidationService().auto_validate(FakeSession(finding), str(finding.id), "t1"))
    assert result["auto_validated"] is False
    assert result["requires_pt"] is True
    assert result["signals"] == []


def test_multiple_signals(monkeypatch):
    _patch_aw(monkeypatch)
    finding = _finding(epss_score=0.9, is_kev=True)
    result = asyncio.run(ValidationService().auto_validate(FakeSession(finding), str(finding.id), "t1"))
    assert "epss_probability" in result["signals"]
    assert "cisa_kev" in result["signals"]
    assert len(result["signals"]) == 2
