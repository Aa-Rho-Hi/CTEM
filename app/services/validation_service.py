from datetime import datetime, timezone

from app.models.entities import Vulnerability
from app.schemas.common import AuditLogCreate
from app.services.audit_writer import AuditWriter

AUTOMATED_VALIDATION_SIGNALS = [
    ("epss_probability", lambda f: (f.epss_score or 0) > 0.7),
    ("cisa_kev", lambda f: bool(f.is_kev)),
    ("exploit_db", lambda f: getattr(f, "exploit_db_id", None) is not None),
    ("threat_actor_ttp", lambda f: getattr(f, "matched_campaign_id", None) is not None),
]


class ValidationService:
    async def auto_validate(self, session, finding_id: str, tenant_id: str) -> dict:
        finding = await session.get(Vulnerability, finding_id)
        if finding is None:
            raise ValueError(f"Finding {finding_id} not found")

        triggered = [
            name for name, check in AUTOMATED_VALIDATION_SIGNALS
            if check(finding)
        ]

        if triggered:
            finding.validation_status = "auto_validated"
            finding.validation_signals = triggered
            finding.validated_at = datetime.now(timezone.utc)
            await session.flush()
            await AuditWriter().write(session, tenant_id, AuditLogCreate(
                action="finding_auto_validated",
                resource_type="vulnerability",
                resource_id=str(finding.id),
                details={"signals": triggered},
            ))

        return {
            "finding_id": finding_id,
            "auto_validated": bool(triggered),
            "signals": triggered,
            "requires_pt": not bool(triggered),
        }
