import asyncio
from types import SimpleNamespace

import pytest

from app.tasks.scan_pipeline import (
    _build_fp_score_pairs,
    _coerce_payload_records,
    _dedupe_enriched_records,
    _partition_prepared_records,
    _run_http_json_scan,
    _synthetic_finding_id,
    enrich_asset,
    _parse_nmap_xml,
    _run_nessus_scan,
    _run_nmap_scan,
    _validate_port_spec,
    _validate_scan_target,
)


def test_scan_pipeline_coerces_json_list_payload():
    payload = '[{"cve_id":"CVE-2026-0001","asset_ip":"10.0.0.10","port":443}]'
    records = _coerce_payload_records(payload, "qualys")
    assert len(records) == 1
    assert records[0]["cve_id"] == "CVE-2026-0001"


def test_scan_pipeline_preserves_mixed_severity_log_payload():
    payload = """
[
  {"timestamp":"2026-04-07T09:15:00Z","severity":"Low","asset":"web-server-01","vulnerability":"Missing Security Headers","status":"Open"},
  {"timestamp":"2026-04-07T09:20:00Z","severity":"Medium","asset":"app-server-02","vulnerability":"Weak Password Policy","status":"Open"},
  {"timestamp":"2026-04-07T09:30:00Z","severity":"High","asset":"db-server-01","vulnerability":"SQL Injection Risk","status":"Investigating"},
  {"timestamp":"2026-04-07T09:45:00Z","severity":"Critical","asset":"auth-server-01","vulnerability":"Remote Code Execution","status":"Escalated"}
]
"""
    records = _coerce_payload_records(payload, "generic")
    severities = [record["severity"] for record in records]
    assert severities == ["Low", "Medium", "High", "Critical"]


def test_synthetic_finding_id_is_stable_for_non_cve_findings():
    class Finding:
        description = "SQL Injection Risk"
        asset_ip = "db-server-01"
        port = None
        source_tool = "generic"

    raw = {"vulnerability": "SQL Injection Risk", "asset": "db-server-01"}
    first = _synthetic_finding_id(raw, Finding())
    second = _synthetic_finding_id(raw, Finding())
    assert first.startswith("GENERIC-")
    assert first == second


def test_partition_prepared_records_keeps_non_cve_findings_and_counts_them():
    prepared_records = [
        ({}, SimpleNamespace(cve_id="CVE-2026-0001"), object(), None, object()),
        ({}, SimpleNamespace(cve_id=None), object(), None, object()),
        ({}, SimpleNamespace(cve_id="CVE-2026-0002"), object(), None, object()),
    ]

    ingest_records, generic_finding_count = _partition_prepared_records(prepared_records)

    assert len(ingest_records) == 3
    assert [record[1].cve_id for record in ingest_records] == ["CVE-2026-0001", None, "CVE-2026-0002"]
    assert generic_finding_count == 1


def test_scan_pipeline_raises_for_unparseable_non_nmap_input():
    with pytest.raises(ValueError):
        _coerce_payload_records("not-json", "qualys")


def test_parse_nmap_xml_extracts_service_finding_without_fake_cve():
    payload = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <hostnames><hostname name="web-01"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.25.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    records = _parse_nmap_xml(payload)
    assert len(records) == 1
    assert records[0]["cve_id"] is None
    assert records[0]["asset_ip"] == "10.0.0.10"
    assert records[0]["port"] == 443
    assert "nginx" in records[0]["description"]


def test_parse_nmap_xml_extracts_cve_from_script_output():
    payload = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.11" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8443">
        <state state="open"/>
        <service name="https"/>
        <script id="vulners" output="CVE-2024-12345 remote issue"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    records = _parse_nmap_xml(payload)
    assert len(records) == 1
    assert records[0]["cve_id"] == "CVE-2024-12345"


def test_validate_scan_target_accepts_ip_and_cidr():
    assert _validate_scan_target("10.0.0.10") == "10.0.0.10"
    assert _validate_scan_target("10.0.0.0/24") == "10.0.0.0/24"


def test_validate_scan_target_rejects_invalid_value():
    with pytest.raises(ValueError):
        _validate_scan_target("10.0.0.999")


def test_validate_port_spec_accepts_ranges_and_lists():
    assert _validate_port_spec("22,80,443,8000-8080") == "22,80,443,8000-8080"


def test_validate_port_spec_rejects_invalid_range():
    with pytest.raises(ValueError):
        _validate_port_spec("70000")
    with pytest.raises(ValueError):
        _validate_port_spec("200-100")


def test_run_nmap_scan_rejects_invalid_target_before_subprocess(monkeypatch):
    monkeypatch.setattr("app.tasks.scan_pipeline.shutil.which", lambda _: "/usr/bin/nmap")

    called = {"value": False}

    def fake_run(*args, **kwargs):
        called["value"] = True
        raise AssertionError("subprocess.run should not be called for invalid targets")

    monkeypatch.setattr("app.tasks.scan_pipeline.subprocess.run", fake_run)

    with pytest.raises(ValueError):
        _run_nmap_scan(["bad-target"], {})

    assert called["value"] is False


def test_run_nmap_scan_rejects_custom_args_before_subprocess(monkeypatch):
    monkeypatch.setattr("app.tasks.scan_pipeline.shutil.which", lambda _: "/usr/bin/nmap")

    called = {"value": False}

    def fake_run(*args, **kwargs):
        called["value"] = True
        raise AssertionError("subprocess.run should not be called when custom args are provided")

    monkeypatch.setattr("app.tasks.scan_pipeline.subprocess.run", fake_run)

    with pytest.raises(ValueError, match="Custom nmap args are not supported"):
        _run_nmap_scan(["10.0.0.10"], {"args": ["--script", "vuln"]})

    assert called["value"] is False


def test_run_nessus_scan_enforces_tls_verification(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"scan": {"id": 1}}

        @property
        def text(self):
            return "<xml></xml>"

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            captured["verify"] = kwargs.get("verify")

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *args, **kwargs):
            return FakeResponse()

        async def get(self, *args, **kwargs):
            raise RuntimeError("stop after verify capture")

    monkeypatch.setattr("httpx.AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(
        "app.tasks.scan_pipeline.validate_public_http_destination",
        lambda url, field_name="url": str(url).rstrip("/"),
    )

    with pytest.raises(RuntimeError, match="stop after verify capture"):
        asyncio.run(
            _run_nessus_scan(
                ["10.0.0.10"],
                {
                    "nessus_url": "https://nessus.example.com",
                    "access_key": "a",
                    "secret_key": "b",
                    "policy_id": "policy",
                },
            )
        )

    assert captured["verify"] is True


def test_run_nessus_scan_rejects_private_url_before_http(monkeypatch):
    called = {"value": False}

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            called["value"] = True

    monkeypatch.setattr("httpx.AsyncClient", FakeAsyncClient)

    with pytest.raises(ValueError, match="nessus_url"):
        asyncio.run(
            _run_nessus_scan(
                ["10.0.0.10"],
                {
                    "nessus_url": "http://10.0.0.5",
                    "access_key": "a",
                    "secret_key": "b",
                    "policy_id": "policy",
                },
            )
        )

    assert called["value"] is False


def test_run_http_json_scan_rejects_private_api_url_before_http(monkeypatch):
    called = {"value": False}

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            called["value"] = True

    monkeypatch.setattr("httpx.AsyncClient", FakeAsyncClient)

    with pytest.raises(ValueError, match="api_url"):
        asyncio.run(
            _run_http_json_scan(
                "snyk",
                ["10.0.0.10"],
                {"api_url": "http://192.168.1.50/scan"},
            )
        )

    assert called["value"] is False


def test_dedupe_enriched_records_removes_batch_duplicate_fingerprints():
    record_a = ({}, object(), object(), None, object(), 80, "dup-fp", None)
    record_b = ({}, object(), object(), None, object(), 75, "dup-fp", None)
    record_c = ({}, object(), object(), None, object(), 70, "unique-fp", None)

    unique_records, skipped = _dedupe_enriched_records(
        [record_a, record_b, record_c],
        existing_duplicate_fps=set(),
    )

    assert len(unique_records) == 2
    assert skipped == 1
    assert unique_records[0][6] == "dup-fp"
    assert unique_records[1][6] == "unique-fp"


def test_build_fp_score_pairs_uses_fingerprint_then_confidence():
    enriched = [
        ({}, object(), object(), None, object(), 81, "fp-one", None),
        ({}, object(), object(), None, object(), 67, "fp-two", None),
    ]

    assert _build_fp_score_pairs(enriched) == [
        ("fp-one", 81),
        ("fp-two", 67),
    ]


def test_enrich_asset_is_deterministic_and_varied():
    first = enrich_asset("10.0.0.5")
    second = enrich_asset("10.0.0.5")
    different = enrich_asset("34.82.10.14")

    assert first == second
    assert 20 <= int(first["asset_criticality"]) <= 100
    assert 0 <= int(first["attack_path_score"]) <= 99
    assert first != different
