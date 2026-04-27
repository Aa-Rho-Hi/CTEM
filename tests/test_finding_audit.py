from types import SimpleNamespace

from app.routes.audit import _entry_matches_finding


def _entry(*, resource_type: str, resource_id: str, details: dict):
    return SimpleNamespace(resource_type=resource_type, resource_id=resource_id, details=details)


def test_entry_matches_finding_direct_vulnerability_event():
    entry = _entry(resource_type="vulnerability", resource_id="finding-1", details={})
    assert _entry_matches_finding(entry, "finding-1", set()) is True


def test_entry_matches_finding_related_remediation_event():
    entry = _entry(resource_type="remediation", resource_id="rem-1", details={})
    assert _entry_matches_finding(entry, "finding-1", {"rem-1"}) is True


def test_entry_matches_finding_via_details_link():
    entry = _entry(resource_type="system", resource_id="other", details={"finding_id": "finding-1"})
    assert _entry_matches_finding(entry, "finding-1", set()) is True


def test_entry_does_not_match_unrelated_finding():
    entry = _entry(resource_type="vulnerability", resource_id="finding-2", details={"finding_id": "finding-2"})
    assert _entry_matches_finding(entry, "finding-1", {"rem-1"}) is False
