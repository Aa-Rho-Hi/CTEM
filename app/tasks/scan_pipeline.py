import shutil
import subprocess
from collections.abc import Iterable
from datetime import datetime, timezone

try:
    from celery import shared_task
except ImportError:  # pragma: no cover
    def shared_task(*args, **kwargs):
        def decorator(func):
            return func

        return decorator
from sqlalchemy import select
try:
    from redis.asyncio import Redis
except ImportError:  # pragma: no cover
    class Redis:
        @staticmethod
        def from_url(url):
            raise RuntimeError("redis package is not installed")

from app.application.discovery.payload_parser import (
    coerce_payload_records as _coerce_payload_records,
    llm_extract_findings as _llm_extract_findings,
)
from app.application.discovery.pipeline import ActiveScanPayloadUseCase, UploadedScanPayloadUseCase
from app.config import get_settings
from app.domain.discovery.scan_parsers import (
    enrich_asset,
    flatten_json as _flatten_json,
    parse_generic_xml as _parse_generic_xml,
    parse_nmap_xml as _parse_nmap_xml,
    parse_observed_at as _parse_observed_at,
    synthetic_finding_id as _synthetic_finding_id,
    validate_nmap_extra_args as _validate_nmap_extra_args,
    validate_port_spec as _validate_port_spec,
    validate_scan_target as _validate_scan_target,
)
from app.models.base import get_scoped_session, reset_async_db_state
from app.models.entities import Asset, ComplianceControl, NetworkZone, Scan, ScanFinding, Vulnerability
from app.services.compliance_mapper import ComplianceMapper
from app.services.confidence_service import ConfidenceService
from app.services.deduplicator import DeduplicatorService
from app.services.discover_service import detect_shadow_assets, normalize_tool_records, parse_external_assets
from app.services.network_validation import validate_public_http_destination
from app.services.nvd_client import NvdClient
from app.services.normalizer import NormalizerService
from app.tasks.compliance_update import recalculate_scores_in_session
from app.tasks.runtime import run_async_task
from app.tasks.risk_scoring import score_scan_findings

BATCH_FLUSH_SIZE = 1000


async def _run_nessus_scan(targets: list[str], options: dict) -> list[dict]:
    """
    Nessus REST API (port 8834).
    Required options: nessus_url, access_key, secret_key, policy_id
    Optional options: folder_id, scan_name
    """
    import httpx, asyncio
    url = options.get("nessus_url", "").rstrip("/")
    access_key = options.get("access_key", "")
    secret_key = options.get("secret_key", "")
    policy_id = options.get("policy_id", "")
    if not all([url, access_key, secret_key, policy_id]):
        raise RuntimeError("Nessus scan requires: nessus_url, access_key, secret_key, policy_id in options.")
    url = validate_public_http_destination(url, field_name="nessus_url")

    headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}", "Content-Type": "application/json"}
    target_str = ",".join(targets)

    async with httpx.AsyncClient(verify=True, timeout=30.0) as client:
        # Create scan
        create_resp = await client.post(f"{url}/scans", headers=headers, json={
            "uuid": policy_id,
            "settings": {
                "name": options.get("scan_name", f"ATLAS-scan-{target_str[:30]}"),
                "text_targets": target_str,
                "folder_id": options.get("folder_id"),
            },
        })
        create_resp.raise_for_status()
        scan_id = create_resp.json()["scan"]["id"]

        # Launch
        await client.post(f"{url}/scans/{scan_id}/launch", headers=headers)

        # Poll until completed (max 30 min)
        for _ in range(120):
            await asyncio.sleep(15)
            status_resp = await client.get(f"{url}/scans/{scan_id}", headers=headers)
            status = status_resp.json().get("info", {}).get("status", "")
            if status == "completed":
                break
            if status in ("canceled", "aborted"):
                raise RuntimeError(f"Nessus scan {scan_id} ended with status: {status}")
        else:
            raise RuntimeError(f"Nessus scan {scan_id} timed out after 30 minutes.")

        # Export as nessus XML
        export_resp = await client.post(f"{url}/scans/{scan_id}/export", headers=headers, json={"format": "nessus"})
        export_resp.raise_for_status()
        file_id = export_resp.json()["file"]

        # Wait for export to be ready
        for _ in range(20):
            await asyncio.sleep(3)
            ready_resp = await client.get(f"{url}/scans/{scan_id}/export/{file_id}/status", headers=headers)
            if ready_resp.json().get("status") == "ready":
                break

        download_resp = await client.get(f"{url}/scans/{scan_id}/export/{file_id}/download", headers=headers)
        download_resp.raise_for_status()

    # Parse as generic XML (Nessus XML contains ReportHost/ReportItem elements)
    return _parse_generic_xml(download_resp.text) or _llm_extract_findings(download_resp.text)


async def _run_qualys_scan(targets: list[str], options: dict) -> list[dict]:
    """
    Qualys VMDR REST API.
    Required options: qualys_url, username, password, option_profile_id
    Optional options: scan_title
    """
    import httpx, asyncio, base64
    url = options.get("qualys_url", "").rstrip("/")
    username = options.get("username", "")
    password = options.get("password", "")
    option_profile_id = options.get("option_profile_id", "")
    if not all([url, username, password, option_profile_id]):
        raise RuntimeError("Qualys scan requires: qualys_url, username, password, option_profile_id in options.")
    url = validate_public_http_destination(url, field_name="qualys_url")

    auth = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {
        "Authorization": f"Basic {auth}",
        "X-Requested-With": "ATLAS-CTEM",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    target_str = ",".join(targets)

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Launch scan
        launch_resp = await client.post(
            f"{url}/api/2.0/fo/scan/",
            headers=headers,
            data={
                "action": "launch",
                "scan_title": options.get("scan_title", f"ATLAS-scan-{target_str[:30]}"),
                "option_id": option_profile_id,
                "ip": target_str,
                "iscanner_name": options.get("scanner_name", "External"),
            },
        )
        launch_resp.raise_for_status()
        # Extract scan ref from XML response
        import xml.etree.ElementTree as _ET
        root = _ET.fromstring(launch_resp.text)
        scan_ref_el = root.find(".//VALUE")
        if scan_ref_el is None:
            raise RuntimeError(f"Qualys scan launch did not return a scan reference. Response: {launch_resp.text[:500]}")
        scan_ref = scan_ref_el.text.strip()

        # Poll until finished (max 30 min)
        for _ in range(90):
            await asyncio.sleep(20)
            list_resp = await client.post(
                f"{url}/api/2.0/fo/scan/",
                headers=headers,
                data={"action": "list", "scan_ref": scan_ref},
            )
            list_root = _ET.fromstring(list_resp.text)
            state_el = list_root.find(".//STATE")
            if state_el is not None and state_el.text == "Finished":
                break
        else:
            raise RuntimeError(f"Qualys scan {scan_ref} timed out.")

        # Fetch results as JSON
        fetch_resp = await client.post(
            f"{url}/api/2.0/fo/scan/",
            headers=headers,
            data={"action": "fetch", "scan_ref": scan_ref, "output_format": "json_extended"},
        )
        fetch_resp.raise_for_status()

    return _flatten_json(fetch_resp.json()) or _llm_extract_findings(fetch_resp.text)


async def _run_openvas_scan(targets: list[str], options: dict) -> list[dict]:
    """
    OpenVAS/GVM via python-gvm library.
    Required options: gvm_url (socket path or host:port), username, password
    Optional options: config_id (defaults to "Full and fast" UUID)
    """
    try:
        from gvm.connections import UnixSocketConnection, TLSConnection  # type: ignore
        from gvm.protocols.gmp import Gmp  # type: ignore
        from gvm.transforms import EtreeCheckCommandTransform  # type: ignore
    except ImportError:
        raise RuntimeError(
            "python-gvm is not installed. Run: pip install python-gvm"
        )

    import asyncio, xml.etree.ElementTree as _ET

    gvm_url = options.get("gvm_url", "/run/gvm/gvmd.sock")
    username = options.get("username", "admin")
    password = options.get("password", "admin")
    # Default "Full and fast" scan config UUID in GVM
    config_id = options.get("config_id", "daba56c8-73ec-11df-a475-002264764cea")

    def _sync_run() -> str:
        if gvm_url.startswith("/"):
            connection = UnixSocketConnection(path=gvm_url)
        else:
            host, _, port = gvm_url.partition(":")
            connection = TLSConnection(hostname=host, port=int(port or 9390))

        with Gmp(connection=connection, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(username, password)

            # Create target
            target_resp = gmp.create_target(
                name=f"ATLAS-target-{targets[0]}",
                hosts=targets,
                port_list_id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5",  # "All IANA assigned TCP"
            )
            target_id = target_resp.get("id")

            # Create task
            task_resp = gmp.create_task(
                name=f"ATLAS-task-{targets[0]}",
                config_id=config_id,
                target_id=target_id,
                scanner_id="08b69003-5fc2-4037-a479-93b440211c73",  # Default OpenVAS scanner
            )
            task_id = task_resp.get("id")

            # Start task
            gmp.start_task(task_id)

            # Poll until done (max 30 min = 120 × 15s)
            import time
            for _ in range(120):
                time.sleep(15)
                task = gmp.get_task(task_id)
                status = task.find(".//status")
                if status is not None and status.text == "Done":
                    break

            # Get report
            tasks = gmp.get_tasks(filter_string=f"id={task_id}")
            report_id = tasks.find(".//last_report/report").get("id")
            report = gmp.get_report(report_id, ignore_pagination=True)
            return _ET.tostring(report, encoding="unicode")

    loop = asyncio.get_event_loop()
    xml_output = await loop.run_in_executor(None, _sync_run)
    return _parse_generic_xml(xml_output) or _llm_extract_findings(xml_output)


async def _run_http_json_scan(tool_name: str, targets: list[str], options: dict) -> list[dict]:
    import httpx

    api_url = options.get("api_url") or options.get("base_url")
    if not api_url:
        mock_findings = options.get("mock_findings")
        if isinstance(mock_findings, list):
            return normalize_tool_records(tool_name, mock_findings)
        return normalize_tool_records(
            tool_name,
            [
                {
                    "cve_id": options.get("cve_id") or "CVE-2026-0001",
                    "asset_ip": targets[0] if targets else "127.0.0.1",
                    "port": options.get("port"),
                    "severity": options.get("severity", "medium"),
                    "description": f"{tool_name} discovered issue on {targets[0] if targets else 'target'}",
                }
            ],
        )
    api_url = validate_public_http_destination(str(api_url), field_name="api_url")

    headers = {"Content-Type": "application/json"}
    if options.get("api_key"):
        headers["Authorization"] = f"Bearer {options['api_key']}"
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            str(api_url),
            headers=headers,
            json={"tool": tool_name, "targets": targets, "options": options},
        )
        response.raise_for_status()
        data = response.json()
    findings = data if isinstance(data, list) else data.get("findings", [])
    return normalize_tool_records(tool_name, findings if isinstance(findings, list) else [])


async def _run_snyk_scan(targets: list[str], options: dict) -> list[dict]:
    return await _run_http_json_scan("snyk", targets, options)


async def _run_checkmarx_scan(targets: list[str], options: dict) -> list[dict]:
    return await _run_http_json_scan("checkmarx", targets, options)


async def _run_sonarqube_scan(targets: list[str], options: dict) -> list[dict]:
    return await _run_http_json_scan("sonarqube", targets, options)


async def _run_rapid7_scan(targets: list[str], options: dict) -> list[dict]:
    return await _run_http_json_scan("rapid7", targets, options)


async def _run_veracode_scan(targets: list[str], options: dict) -> list[dict]:
    return await _run_http_json_scan("veracode", targets, options)


async def _run_burp_suite_scan(targets: list[str], options: dict) -> list[dict]:
    return await _run_http_json_scan("burp_suite", targets, options)


async def _discover_external_attack_surface(tenant_id: str, options: dict) -> dict:
    async with get_scoped_session(tenant_id) as session:
        known_assets = (await session.execute(select(Asset))).scalars().all()
        ct_assets = parse_external_assets(options.get("ct_assets") or options.get("certificate_transparency_results") or [])
        internet_assets = parse_external_assets(options.get("internet_assets") or options.get("enumeration_results") or [])
        cloud_resources = parse_external_assets(options.get("cloud_resources") or [])

        known_ips = {asset.ip_address for asset in known_assets if getattr(asset, "ip_address", None)}
        known_hostnames = {asset.hostname.lower() for asset in known_assets if getattr(asset, "hostname", None)}
        created_assets = []

        for candidate in [*ct_assets, *internet_assets]:
            hostname = candidate.get("hostname")
            public_ip = candidate.get("public_ip")
            if public_ip in known_ips or (hostname and hostname.lower() in known_hostnames):
                continue
            asset = Asset(
                hostname=hostname or public_ip or "external-asset",
                ip_address=public_ip or "0.0.0.0",
                criticality_score=35,
                business_context={
                    "external_attack_surface": True,
                    "discovered_via": candidate.get("source"),
                },
            )
            session.add(asset)
            await session.flush()
            created_assets.append({"id": str(asset.id), "hostname": asset.hostname, "ip_address": asset.ip_address})
            if asset.ip_address:
                known_ips.add(asset.ip_address)
            if asset.hostname:
                known_hostnames.add(asset.hostname.lower())

        shadow_assets = detect_shadow_assets(cloud_resources, known_assets)
        await session.commit()
        return {
            "external_assets": created_assets,
            "shadow_assets": shadow_assets,
            "ct_asset_count": len(ct_assets),
            "internet_asset_count": len(internet_assets),
        }


def _run_nmap_scan(targets: list[str], options: dict) -> str:
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise RuntimeError("nmap is not installed or not available on PATH.")

    command = [nmap_path, "-oX", "-", "-Pn", "-T4", "-sV"]
    validated_targets = [_validate_scan_target(target) for target in targets]
    ports = options.get("ports")
    if isinstance(ports, str) and ports.strip():
        command.extend(["-p", _validate_port_spec(ports)])
    _validate_nmap_extra_args(options.get("args"))
    command.extend(validated_targets)

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip() or "unknown nmap execution failure"
        raise RuntimeError(f"nmap scan failed: {stderr}")
    if not completed.stdout.strip():
        raise RuntimeError("nmap scan completed without XML output.")
    return completed.stdout


async def _get_or_create_asset(session, asset_ip: str):
    asset = (await session.execute(select(Asset).where(Asset.ip_address == asset_ip))).scalar_one_or_none()
    if asset is not None:
        return asset
    enrichment = enrich_asset(asset_ip)
    asset = Asset(hostname=asset_ip, ip_address=asset_ip, criticality_score=50, business_context={})
    asset.criticality_score = int(enrichment["asset_criticality"])
    asset.business_context = {
        "business_impact": enrichment["business_impact"],
        "internet_exposed": enrichment["internet_exposed"],
        "external_attack_surface": enrichment["internet_exposed"],
        "is_crown_jewel": enrichment["is_crown_jewel"],
        "attack_path_score": enrichment["attack_path_score"],
    }
    session.add(asset)
    await session.flush()
    return asset


async def _bulk_corroborating_sources(
    session, tenant_id: str, cve_port_pairs: list[tuple[str, int | None]]
) -> dict[tuple[str, int | None], set[str]]:
    """Fetch corroborating source_tools for all (cve_id, port) pairs in one query."""
    if not cve_port_pairs:
        return {}
    unique_cves = {cve for cve, _ in cve_port_pairs}
    rows = (
        await session.execute(
            select(Vulnerability.cve_id, Vulnerability.port, Vulnerability.source_tool).where(
                Vulnerability.tenant_id == tenant_id,
                Vulnerability.cve_id.in_(unique_cves),
                Vulnerability.asset_id.is_not(None),
            )
        )
    ).all()
    result: dict[tuple[str, int | None], set[str]] = {}
    for cve_id, port, src in rows:
        key = (cve_id, port)
        if key not in result:
            result[key] = set()
        if src:
            result[key].add(src.lower())
    return result


def _batched(items: list, batch_size: int = BATCH_FLUSH_SIZE) -> Iterable[list]:
    for idx in range(0, len(items), batch_size):
        yield items[idx : idx + batch_size]


def _dedupe_enriched_records(
    enriched: list[tuple],
    existing_duplicate_fps: set[str],
) -> tuple[list[tuple], int]:
    """
    Remove records whose fingerprint already exists in DB and collapse duplicates
    repeated within the same upload batch.
    Returns the unique records to insert and the number of skipped duplicates.
    """
    seen_fps: set[str] = set()
    unique_records: list[tuple] = []
    skipped_duplicates = 0

    for record in enriched:
        fingerprint_hash = record[6]
        if fingerprint_hash in existing_duplicate_fps or fingerprint_hash in seen_fps:
            skipped_duplicates += 1
            continue
        seen_fps.add(fingerprint_hash)
        unique_records.append(record)

    return unique_records, skipped_duplicates


def _build_fp_score_pairs(enriched: list[tuple]) -> list[tuple[str, int]]:
    return [(record[6], record[5]) for record in enriched]


def _partition_prepared_records(
    prepared_records: list[tuple[dict, object, Asset, NetworkZone | None, ScanFinding]],
) -> tuple[list[tuple[dict, object, Asset, NetworkZone | None, ScanFinding]], int]:
    generic_finding_count = sum(1 for record in prepared_records if not getattr(record[1], "cve_id", None))
    return prepared_records, generic_finding_count


async def _flush_vulnerability_batch(
    session,
    batch: list[tuple[Vulnerability, NetworkZone | None, Asset]],
    nvd_map: dict[str, dict],
    compliance_mapper: ComplianceMapper,
    created_vulnerability_ids: list[str],
):
    if not batch:
        return

    await session.flush()
    for vulnerability, zone, asset in batch:
        enrichment = nvd_map.get(vulnerability.cve_id, {})
        vulnerability.cvss_score = enrichment.get("cvss_base_score", 0)
        vulnerability.cvss_vector = enrichment.get("cvss_vector")
        vulnerability.epss_score = enrichment.get("epss_probability", 0)
        vulnerability.is_kev = enrichment.get("is_kev", False)
        vulnerability.cwe_id = enrichment.get("cwe_id")
        print(
            "INGEST_ENRICHMENT",
            {
                "cve_id": vulnerability.cve_id,
                "asset_ip": asset.ip_address,
                "cvss_base": vulnerability.cvss_score,
                "epss": vulnerability.epss_score,
                "kev": vulnerability.is_kev,
                "asset_criticality": asset.criticality_score,
                "internet_exposed": bool((asset.business_context or {}).get("internet_exposed")),
                "attack_path_score": (asset.business_context or {}).get("attack_path_score", 0),
            },
        )
        controls = await compliance_mapper.ingest_vulnerability_controls(session, vulnerability, zone, asset)
        if controls:
            first_control = await session.get(ComplianceControl, controls[0].control_id)
            if first_control is not None:
                vulnerability.compliance_framework_id = first_control.framework_id
        created_vulnerability_ids.append(str(vulnerability.id))


async def _ingest_scan(scan_id: str, tenant_id: str, payload_records: list[dict], source_tool: str) -> dict:
    normalizer = NormalizerService()
    deduplicator = DeduplicatorService()
    confidence_service = ConfidenceService()
    compliance_mapper = ComplianceMapper()
    created_vulnerability_ids: list[str] = []
    settings = get_settings()
    redis = Redis.from_url(settings.redis_url)
    async with get_scoped_session(tenant_id) as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            await redis.aclose()
            return {"scan_id": scan_id, "ingested": 0}
        duplicate_count = 0
        asset_cache: dict[str, Asset] = {}
        zone_cache: dict[str, NetworkZone | None] = {}
        prepared_records: list[tuple[dict, object, Asset, NetworkZone | None, ScanFinding]] = []
        pending_scan_findings: list[ScanFinding] = []

        # PASS 1: Normalize all records and bulk-flush ScanFindings (unchanged)
        for raw_record in payload_records:
            normalized = normalizer.normalize(raw_record, source_tool, tenant_id)
            asset_ip = normalized.asset_ip or "0.0.0.0"
            asset = asset_cache.get(asset_ip)
            if asset is None:
                asset = await _get_or_create_asset(session, asset_ip)
                asset_cache[asset_ip] = asset

            zone = None
            if asset.zone_id:
                zone_key = str(asset.zone_id)
                if zone_key not in zone_cache:
                    zone_cache[zone_key] = await session.get(NetworkZone, asset.zone_id)
                zone = zone_cache[zone_key]

            scan_finding = ScanFinding(
                scan_id=scan.id,
                asset_id=asset.id,
                raw_payload=raw_record,
                normalized_payload=normalized.model_dump(),
            )
            session.add(scan_finding)
            pending_scan_findings.append(scan_finding)
            prepared_records.append((raw_record, normalized, asset, zone, scan_finding))

            if len(pending_scan_findings) >= BATCH_FLUSH_SIZE:
                await session.flush()
                pending_scan_findings.clear()

        if pending_scan_findings:
            await session.flush()

        ingest_records, generic_finding_count = _partition_prepared_records(prepared_records)
        skipped_no_cve_count = 0

        # BULK FETCH 1: corroborating sources — 1 query instead of N
        cve_port_pairs = list({(norm.cve_id, norm.port) for _, norm, _, _, _ in ingest_records if norm.cve_id})
        corroborating_map = await _bulk_corroborating_sources(session, tenant_id, cve_port_pairs)

        # BULK FETCH 2: NVD enrichment — 1 Redis mget instead of N individual gets
        unique_cve_ids = list({norm.cve_id for _, norm, _, _, _ in ingest_records if norm.cve_id})
        nvd_map = await NvdClient(redis).bulk_fetch(unique_cve_ids)

        # Compute confidence scores and fingerprints for all parsed records.
        enriched: list[tuple[dict, object, Asset, NetworkZone | None, ScanFinding, int, str]] = []
        for raw_record, normalized, asset, zone, scan_finding in ingest_records:
            finding_id = normalized.cve_id or _synthetic_finding_id(raw_record, normalized)
            sources = corroborating_map.get((normalized.cve_id, normalized.port), set()) if normalized.cve_id else set()
            corroborating = len(sources - {normalized.source_tool.lower()})
            observed_at = normalized.observed_at or raw_record.get("observed_at") or raw_record.get("first_seen") or raw_record.get("last_seen")
            confidence_score = confidence_service.score(
                normalized,
                corroborating_sources=corroborating,
                observed_at=observed_at or (scan.created_at.isoformat() if scan.created_at else None),
            )
            fingerprint_hash = deduplicator.fingerprint(
                finding_id,
                normalized.asset_ip or "0.0.0.0",
                normalized.source_tool,
                normalized.port,
            )
            enriched.append((raw_record, normalized, asset, zone, scan_finding, confidence_score, fingerprint_hash, _parse_observed_at(observed_at), finding_id))

        # BULK FETCH 3: duplicate check + update — 1 query instead of N
        fp_score_pairs = _build_fp_score_pairs(enriched)
        duplicate_fps = await deduplicator.bulk_check_and_update(session, fp_score_pairs)
        unique_enriched, skipped_duplicate_count = _dedupe_enriched_records(enriched, duplicate_fps)
        duplicate_count = skipped_duplicate_count

        # PASS 2: Create new Vulnerabilities (non-duplicates only)
        pending_vulnerabilities: list[tuple[Vulnerability, NetworkZone | None, Asset]] = []
        for _, normalized, asset, zone, scan_finding, confidence_score, fingerprint_hash, observed_at, finding_id in unique_enriched:
            vulnerability = Vulnerability(
                asset_id=asset.id,
                scan_finding_id=scan_finding.id,
                cve_id=finding_id,
                source_tool=normalized.source_tool,
                port=normalized.port,
                fingerprint_hash=fingerprint_hash,
                severity=normalized.severity.title(),
                confidence_score=confidence_score,
                first_seen=observed_at or datetime.now(timezone.utc),
                last_seen=observed_at or datetime.now(timezone.utc),
            )
            session.add(vulnerability)
            pending_vulnerabilities.append((vulnerability, zone, asset))

            if len(pending_vulnerabilities) >= BATCH_FLUSH_SIZE:
                await _flush_vulnerability_batch(
                    session,
                    pending_vulnerabilities,
                    nvd_map,
                    compliance_mapper,
                    created_vulnerability_ids,
                )
                pending_vulnerabilities.clear()

        if pending_vulnerabilities:
            await _flush_vulnerability_batch(
                session,
                pending_vulnerabilities,
                nvd_map,
                compliance_mapper,
                created_vulnerability_ids,
            )
        metadata = dict(scan.metadata_json or {})
        metadata["duplicate_count"] = duplicate_count
        metadata["skipped_no_cve_count"] = skipped_no_cve_count
        metadata["generic_finding_count"] = generic_finding_count
        metadata["scan_finding_count"] = len(prepared_records)
        metadata["ingested_count"] = len(created_vulnerability_ids)
        metadata["vulnerability_ids"] = created_vulnerability_ids
        scan.metadata_json = metadata
        scan.status = "ready"
        await recalculate_scores_in_session(session, tenant_id)
        await session.commit()
    await redis.aclose()
    return {
        "scan_id": scan_id,
        "ingested": len(created_vulnerability_ids),
        "vulnerability_ids": created_vulnerability_ids,
        "duplicate_count": duplicate_count,
        "skipped_no_cve_count": skipped_no_cve_count,
    }


async def _update_scan_status(scan_id: str, status: str, error: str | None = None) -> None:
    async with get_scoped_session(None) as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = status
        metadata = dict(scan.metadata_json or {})
        if error:
            metadata["error"] = error
        elif "error" in metadata:
            metadata.pop("error", None)
        scan.metadata_json = metadata
        await session.commit()


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def process_active_scan(self, scan_id: str) -> dict:
    reset_async_db_state()

    async def _load_scan():
        async with get_scoped_session(None) as session:
            return await session.get(Scan, scan_id)

    scan = run_async_task(_load_scan())
    if scan is not None:
        try:
            run_async_task(_update_scan_status(scan_id, "processing"))
            payload_batch = run_async_task(
                ActiveScanPayloadUseCase(
                    run_nmap_scan=_run_nmap_scan,
                    parse_nmap_xml=_parse_nmap_xml,
                    run_nessus_scan=_run_nessus_scan,
                    run_qualys_scan=_run_qualys_scan,
                    run_openvas_scan=_run_openvas_scan,
                    run_snyk_scan=_run_snyk_scan,
                    run_checkmarx_scan=_run_checkmarx_scan,
                    run_sonarqube_scan=_run_sonarqube_scan,
                    run_rapid7_scan=_run_rapid7_scan,
                    run_veracode_scan=_run_veracode_scan,
                    run_burp_suite_scan=_run_burp_suite_scan,
                ).execute(scan=scan)
            )
            result = run_async_task(
                _ingest_scan(scan_id, str(scan.tenant_id), payload_batch.payload_records, scan.source_tool)
            )
            score_scan_findings.delay(scan_id, str(scan.tenant_id))
            return result | payload_batch.extra
        except Exception as exc:
            if self.request.retries >= self.max_retries:
                run_async_task(_update_scan_status(scan_id, "failed", str(exc)))
            raise
    return {"scan_id": scan_id, "status": "missing"}


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def process_uploaded_scan(self, scan_id: str, payload: str = "") -> dict:
    reset_async_db_state()

    async def _load_scan():
        async with get_scoped_session(None) as session:
            return await session.get(Scan, scan_id)

    scan = run_async_task(_load_scan())
    if scan is not None:
        try:
            run_async_task(_update_scan_status(scan_id, "processing"))
            payload_batch = run_async_task(
                UploadedScanPayloadUseCase(coerce_payload_records=_coerce_payload_records).execute(
                    scan=scan,
                    payload=payload,
                )
            )
            result = run_async_task(
                _ingest_scan(scan_id, str(scan.tenant_id), payload_batch.payload_records, scan.source_tool)
            )
            score_scan_findings.delay(scan_id, str(scan.tenant_id))
            return result | payload_batch.extra
        except Exception as exc:
            if self.request.retries >= self.max_retries:
                run_async_task(_update_scan_status(scan_id, "failed", str(exc)))
            raise
    return {"scan_id": scan_id, "status": "missing"}


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def discover_external_attack_surface(self, tenant_id: str, options: dict | None = None) -> dict:
    reset_async_db_state()
    return run_async_task(_discover_external_attack_surface(tenant_id, options or {}))
