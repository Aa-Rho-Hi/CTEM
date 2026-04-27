import inspect
from pathlib import Path

from sqlalchemy import select

from app.models.entities import Vulnerability
from app.routes.mobilize import approval_queue
from app.routes.prioritize import _apply_finding_filters, list_findings
from app.services.nvd_client import NvdClient
from app.tasks.scan_pipeline import BATCH_FLUSH_SIZE, _batched, _ingest_scan


def test_nvd_client_timeout_budget_is_capped():
    assert NvdClient.HTTP_TIMEOUT_SECONDS <= 0.5


def test_scan_pipeline_batches_in_thousands():
    items = list(range(2505))
    batches = list(_batched(items))
    assert BATCH_FLUSH_SIZE == 1000
    assert [len(batch) for batch in batches] == [1000, 1000, 505]

    source = inspect.getsource(_ingest_scan)
    assert "BATCH_FLUSH_SIZE" in source
    assert "_flush_vulnerability_batch" in source


def test_approval_queue_is_paginated_and_joined():
    source = inspect.getsource(approval_queue)
    assert ".limit(limit)" in source
    assert ".offset(offset)" in source
    assert "select(Remediation, Vulnerability, Asset, BlastRadiusSnapshot, DryRunOutput)" in source


def test_findings_route_supports_cve_search_filter():
    source = inspect.getsource(list_findings)
    assert "cve_id: str | None = None" in source
    assert "cve_id=cve_id" in source


def test_apply_finding_filters_adds_cve_id_search_clause():
    statement = _apply_finding_filters(
        select(Vulnerability.id),
        severity=None,
        status=None,
        sla_tier=None,
        asset_id=None,
        source_tool=None,
        cve_id="CVE-2026-1234",
    )

    sql = str(statement)
    assert "vulnerabilities.cve_id" in sql
    assert "LIKE" in sql.upper()


def test_api_hpa_manifest_matches_requirement():
    manifest = Path("k8s/api-hpa.yaml").read_text()
    assert "minReplicas: 2" in manifest
    assert "maxReplicas: 10" in manifest
    assert "averageUtilization: 70" in manifest


def test_worker_hpa_manifest_matches_requirement():
    manifest = Path("k8s/worker-hpa.yaml").read_text()
    assert "minReplicas: 2" in manifest
    assert "maxReplicas: 20" in manifest
    assert "averageUtilization: 60" in manifest
