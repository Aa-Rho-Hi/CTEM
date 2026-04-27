from dataclasses import dataclass

from sqlalchemy import func, select

from app.models.entities import Scan, ScanFinding, Vulnerability


@dataclass(slots=True)
class ScanStatusRecord:
    id: object
    source_tool: str
    status: str
    created_at: object
    metadata_json: dict
    finding_count: int
    vulnerability_count: int


class DiscoveryRepository:
    def __init__(self, session):
        self.session = session

    async def create_scan(self, *, source_tool: str, status: str, metadata_json: dict) -> Scan:
        scan = Scan(source_tool=source_tool, status=status, metadata_json=metadata_json)
        self.session.add(scan)
        await self.session.commit()
        return scan

    async def get_scan_status_record(self, scan_id: str) -> ScanStatusRecord | None:
        scan = await self.session.get(Scan, scan_id)
        if scan is None:
            return None

        finding_count = (
            await self.session.execute(select(func.count(ScanFinding.id)).where(ScanFinding.scan_id == scan.id))
        ).scalar_one()
        vulnerability_count = (
            await self.session.execute(
                select(func.count(Vulnerability.id)).where(
                    Vulnerability.scan_finding_id.in_(select(ScanFinding.id).where(ScanFinding.scan_id == scan.id))
                )
            )
        ).scalar_one()
        return ScanStatusRecord(
            id=scan.id,
            source_tool=scan.source_tool,
            status=scan.status,
            created_at=scan.created_at,
            metadata_json=scan.metadata_json or {},
            finding_count=finding_count,
            vulnerability_count=vulnerability_count,
        )

    def current_tenant_id(self) -> str | None:
        tenant_id = self.session.info.get("tenant_id")
        return str(tenant_id) if tenant_id is not None else None
