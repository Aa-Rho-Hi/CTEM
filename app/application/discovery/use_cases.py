from dataclasses import dataclass

PROCESS_ACTIVE_SCAN_TASK = "app.tasks.scan_pipeline.process_active_scan"
PROCESS_UPLOADED_SCAN_TASK = "app.tasks.scan_pipeline.process_uploaded_scan"
DISCOVER_EXTERNAL_ATTACK_SURFACE_TASK = "app.tasks.scan_pipeline.discover_external_attack_surface"


class ScanNotFoundError(LookupError):
    pass


@dataclass(slots=True)
class ScanStatusResult:
    id: str
    source_tool: str
    status: str
    created_at: str | None
    finding_count: int
    vulnerability_count: int
    vulnerability_ids: list[str]
    duplicate_count: int
    skipped_no_cve_count: int
    generic_finding_count: int
    error: str | None


def external_discovery_options_for_environment(environment: str) -> dict:
    if environment != "development":
        return {}
    return {
        "certificate_transparency_results": [
            {
                "domain": "portal.atlas-demo.local",
                "public_ip": "34.82.10.14",
                "source": "certificate_transparency",
                "provider": "gcp",
            },
            {
                "domain": "vpn.atlas-demo.local",
                "public_ip": "52.12.44.21",
                "source": "certificate_transparency",
                "provider": "aws",
            },
        ],
        "enumeration_results": [
            {
                "hostname": "cdn.atlas-demo.local",
                "public_ip": "104.18.10.25",
                "source": "internet_enumerator",
                "provider": "cloudflare",
            }
        ],
        "cloud_resources": [
            {
                "hostname": "portal.atlas-demo.local",
                "public_ip": "34.82.10.14",
                "provider": "gcp",
                "account": "prod",
            },
            {
                "hostname": "shadow-admin.atlas-demo.local",
                "public_ip": "18.144.22.90",
                "provider": "aws",
                "account": "legacy-prod",
            },
        ],
    }


class StartActiveScanUseCase:
    def __init__(self, repository, task_queue, *, canonical_tool_name):
        self.repository = repository
        self.task_queue = task_queue
        self.canonical_tool_name = canonical_tool_name

    async def execute(self, payload) -> str:
        scan = await self.repository.create_scan(
            source_tool=self.canonical_tool_name(payload.source_tool),
            status="queued",
            metadata_json=payload.model_dump(),
        )
        self.task_queue.send_task(PROCESS_ACTIVE_SCAN_TASK, args=[str(scan.id)])
        return str(scan.id)


class UploadScanUseCase:
    def __init__(self, repository, task_queue, *, infer_source_tool):
        self.repository = repository
        self.task_queue = task_queue
        self.infer_source_tool = infer_source_tool

    async def execute(self, *, filename: str | None, content: str) -> str:
        source_tool = self.infer_source_tool(filename or "upload", content)
        scan = await self.repository.create_scan(
            source_tool=source_tool,
            status="uploaded",
            metadata_json={"filename": filename, "raw_content": content},
        )
        self.task_queue.send_task(PROCESS_UPLOADED_SCAN_TASK, args=[str(scan.id)])
        return str(scan.id)


class GetScanStatusUseCase:
    def __init__(self, repository):
        self.repository = repository

    async def execute(self, scan_id: str) -> ScanStatusResult:
        scan = await self.repository.get_scan_status_record(scan_id)
        if scan is None:
            raise ScanNotFoundError("Scan not found.")

        metadata = scan.metadata_json or {}
        return ScanStatusResult(
            id=str(scan.id),
            source_tool=scan.source_tool,
            status=scan.status,
            created_at=scan.created_at.isoformat() if scan.created_at else None,
            finding_count=scan.finding_count,
            vulnerability_count=scan.vulnerability_count,
            vulnerability_ids=[str(item) for item in (metadata.get("vulnerability_ids") or []) if item],
            duplicate_count=int(metadata.get("duplicate_count", 0) or 0),
            skipped_no_cve_count=int(metadata.get("skipped_no_cve_count", 0) or 0),
            generic_finding_count=int(metadata.get("generic_finding_count", 0) or 0),
            error=metadata.get("error"),
        )


class RefreshExternalDiscoveryUseCase:
    def __init__(self, repository, task_queue, *, environment: str):
        self.repository = repository
        self.task_queue = task_queue
        self.environment = environment

    async def execute(self) -> str:
        self.task_queue.send_task(
            DISCOVER_EXTERNAL_ATTACK_SURFACE_TASK,
            args=[self.repository.current_tenant_id(), external_discovery_options_for_environment(self.environment)],
        )
        return "queued"
