import asyncio
import hashlib
from datetime import datetime, timedelta, timezone

try:
    from celery import shared_task
except ImportError:  # pragma: no cover
    def shared_task(*args, **kwargs):
        def decorator(func):
            return func

        return decorator
try:
    from redis.asyncio import Redis
except ImportError:  # pragma: no cover
    Redis = object
from sqlalchemy import select

from app.config import get_settings
from app.models.base import get_scoped_session, reset_async_db_state
from app.models.entities import Asset, AttackGraphNode, ComplianceControl, CrownJewelTier, NetworkZone, Scan, ScanFinding, Vulnerability
from app.services.attack_graph import AttackGraphService
from app.services.audit_writer import AuditWriter
from app.services.compliance_mapper import ComplianceMapper
from app.services.nvd_client import NvdClient
from app.services.risk_engine import RiskEngine
from app.services.threat_actor import ThreatActorMapper
from app.tasks.compliance_update import recalculate_scores_in_session
from app.tasks.runtime import run_async_task


def compute_attack_path_score(asset_ip: str) -> int:
    digest = hashlib.sha256(asset_ip.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 100


GENERIC_SEVERITY_SCORE = {
    "critical": (95, "Critical", 1),
    "high": (75, "High", 7),
    "medium": (55, "Medium", 30),
    "low": (25, "Low", 90),
    "info": (10, "Low", 90),
}


async def _score_vulnerability(vulnerability_id: str, tenant_id: str) -> dict:
    settings = get_settings()
    redis = Redis.from_url(settings.redis_url)
    async with get_scoped_session(tenant_id) as session:
        vulnerability = await session.get(Vulnerability, vulnerability_id)
        if vulnerability is None:
            return {"status": "missing"}
        if vulnerability.cve_id.startswith("GENERIC-"):
            scan_finding = await session.get(ScanFinding, vulnerability.scan_finding_id) if vulnerability.scan_finding_id else None
            normalized_payload = (scan_finding.normalized_payload or {}) if scan_finding else {}
            source_severity = str(normalized_payload.get("severity") or vulnerability.severity or "low").strip().lower()
            score, severity, sla_days = GENERIC_SEVERITY_SCORE.get(source_severity, GENERIC_SEVERITY_SCORE["low"])
            vulnerability.cvss_score = 0
            vulnerability.epss_score = 0
            vulnerability.is_kev = False
            vulnerability.risk_score = score
            vulnerability.severity = severity
            vulnerability.sla_tier = severity
            vulnerability.sla_due_date = datetime.now(timezone.utc) + timedelta(days=sla_days)
            await session.commit()
            await redis.aclose()
            return {
                "vulnerability_id": str(vulnerability.id),
                "risk_score": vulnerability.risk_score,
                "severity": vulnerability.severity,
                "sla_tier": vulnerability.sla_tier,
                "exploitability_score": 0,
                "exposure_score": 0,
                "business_impact_score": 0,
            }

        asset = await session.get(Asset, vulnerability.asset_id) if vulnerability.asset_id else None
        zone = await session.get(NetworkZone, asset.zone_id) if asset and asset.zone_id else None
        tier = await session.get(CrownJewelTier, asset.crown_jewel_tier_id) if asset and asset.crown_jewel_tier_id else None
        attack_graph_node = (
            (
                await session.execute(
                    select(AttackGraphNode).where(
                        AttackGraphNode.reference_id == str(asset.id),
                        AttackGraphNode.node_type == "asset",
                    )
                )
            ).scalars().first()
            if asset
            else None
        )

        enrichment = await NvdClient(redis).fetch(vulnerability.cve_id)
        vulnerability.cvss_score = enrichment["cvss_base_score"]
        vulnerability.cvss_vector = enrichment["cvss_vector"]
        vulnerability.epss_score = enrichment["epss_probability"]
        vulnerability.is_kev = enrichment["is_kev"]
        vulnerability.cwe_id = enrichment.get("cwe_id")

        result = await RiskEngine().apply_to_vulnerability(
            vulnerability,
            cvss_base=enrichment["cvss_base_score"],
            epss_prob=enrichment["epss_probability"],
            kev_flag=enrichment["is_kev"],
            exploit_confirmed=False,
            asset_criticality=asset.criticality_score if asset else 0,
            crown_jewel_tier=(
                tier.name
                if tier
                else ("tier_1" if asset and (asset.business_context or {}).get("is_crown_jewel") else None)
            ),
            exploit_available=bool(enrichment["is_kev"] or enrichment["epss_probability"] >= 0.7),
            false_positive_inputs={
                "asset_type_match": 0.3,
                "port_context": 0.2 if vulnerability.port in {80, 443, 22, 3389} else 0.8,
                "cve_age": 0.5,
                "cross_source_confirmation": 0.1,
            },
            exposure_context={
                "internet_exposed": bool((asset.business_context or {}).get("internet_exposed") or (asset.business_context or {}).get("external_attack_surface")) if asset else False,
                "external_attack_surface": bool((asset.business_context or {}).get("external_attack_surface")) if asset else False,
                "regulated_zone": bool((zone and (zone.pci or zone.hipaa))),
                "high_lateral_movement": bool(zone is not None),
            },
            business_context=(asset.business_context or {}) if asset else {},
            attack_path_context={
                "centrality_score": (
                    attack_graph_node.centrality_score
                    if attack_graph_node
                    else (compute_attack_path_score(asset.ip_address) / 100.0 if asset else 0.0)
                ),
                "is_choke_point": attack_graph_node.is_choke_point if attack_graph_node else False,
                "near_crown_jewel": bool(asset and (asset.crown_jewel_tier_id or (asset.business_context or {}).get("is_crown_jewel"))),
                "attack_path_count": max(1, compute_attack_path_score(asset.ip_address) // 20) if asset else 0,
            },
            audit_writer=AuditWriter(),
            session=session,
            tenant_id=tenant_id,
        )
        print(
            "RISK_DEBUG",
            {
                "cve_id": vulnerability.cve_id,
                "cvss_base": enrichment["cvss_base_score"],
                "epss": enrichment["epss_probability"],
                "asset_criticality": asset.criticality_score if asset else 0,
                "internet_exposed": bool((asset.business_context or {}).get("internet_exposed")) if asset else False,
                "attack_path_score": compute_attack_path_score(asset.ip_address) if asset else 0,
                "final_score": result.score,
                "severity": result.severity,
            },
        )

        await ThreatActorMapper().apply_campaign_bonus(
            session,
            vulnerability,
            industry_sector=asset.business_context.get("industry_sector") if asset else None,
        )
        controls = await ComplianceMapper().ingest_vulnerability_controls(session, vulnerability, zone)
        if controls:
            first_control = await session.get(ComplianceControl, controls[0].control_id)
            if first_control is not None:
                vulnerability.compliance_framework_id = first_control.framework_id
        await session.commit()
        await redis.aclose()

        from app.services.splunk import SplunkService
        await SplunkService().send_event(
            sourcetype="atlas:risk_score",
            event={
                "vulnerability_id": str(vulnerability.id),
                "cve_id": vulnerability.cve_id,
                "risk_score": vulnerability.risk_score,
                "severity": vulnerability.severity,
                "sla_tier": vulnerability.sla_tier,
                "is_kev": vulnerability.is_kev,
                "cvss_score": vulnerability.cvss_score,
                "epss_score": vulnerability.epss_score,
                "exploitability_score": result.exploitability_score,
                "exposure_score": result.exposure_score,
                "business_impact_score": result.business_impact_score,
                "tenant_id": tenant_id,
            },
        )
        return {
            "vulnerability_id": str(vulnerability.id),
            "risk_score": vulnerability.risk_score,
            "severity": vulnerability.severity,
            "sla_tier": vulnerability.sla_tier,
            "exploitability_score": result.exploitability_score,
            "exposure_score": result.exposure_score,
            "business_impact_score": result.business_impact_score,
        }


async def _bulk_score_scan(scan_id: str, tenant_id: str) -> dict:
    settings = get_settings()
    redis = Redis.from_url(settings.redis_url)
    async with get_scoped_session(tenant_id) as session:
        vulnerabilities = (
            await session.execute(
                select(Vulnerability)
                .join(ScanFinding, Vulnerability.scan_finding_id == ScanFinding.id)
                .where(Vulnerability.scan_finding_id.is_not(None), ScanFinding.scan_id == scan_id)
                .limit(1000)
            )
        ).scalars().all()
    results = []
    for vulnerability in vulnerabilities:
        results.append(await _score_vulnerability(str(vulnerability.id), tenant_id))
    # Rebuild attack graph and recalculate compliance once after all vulnerabilities are scored
    async with get_scoped_session(tenant_id) as session:
        await AttackGraphService().rebuild_for_tenant(session, tenant_id)
        await recalculate_scores_in_session(session, tenant_id)
        scan = await session.get(Scan, scan_id)
        if scan is not None:
            scan.status = "processed"
            metadata = dict(scan.metadata_json or {})
            metadata["rescored_count"] = len(results)
            scan.metadata_json = metadata
        await session.commit()
    try:
        await redis.delete(f"attack_surface:{tenant_id}", f"attack_surface:v2:{tenant_id}")
        await redis.aclose()
    except Exception:
        pass
    return {"scan_id": scan_id, "processed": len(results)}


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def rescore_vulnerability(self, vulnerability_id: str, tenant_id: str) -> dict:
    reset_async_db_state()
    return run_async_task(_score_vulnerability(vulnerability_id, tenant_id))


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def score_scan_findings(self, scan_id: str, tenant_id: str) -> dict:
    reset_async_db_state()
    return run_async_task(_bulk_score_scan(scan_id, tenant_id))
