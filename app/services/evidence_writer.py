from app.models.entities import PtEvidence
from app.schemas.common import AuditLogCreate
from app.services.audit_writer import AuditWriter


class EvidenceWriter:
    async def write(
        self,
        session,
        *,
        session_id: str,
        agent_id: str,
        exploit_type: str,
        tool_used: str,
        payload: str,
        response: str,
        exploitation_confirmed: bool,
        tenant_id: str,
    ) -> PtEvidence:
        evidence = PtEvidence(
            pt_session_id=session_id,
            agent_id=agent_id,
            exploit_type=exploit_type,
            tool_used=tool_used,
            payload={"raw": payload},
            response={"raw": response},
            confirmed=exploitation_confirmed,
            exploitation_confirmed=exploitation_confirmed,
            tenant_id=tenant_id,
        )
        session.add(evidence)
        await session.flush()
        await AuditWriter().write(session, tenant_id, AuditLogCreate(
            action="pt_evidence_recorded",
            resource_type="pt_evidence",
            resource_id=str(evidence.id),
            details={
                "session_id": session_id,
                "exploit_type": exploit_type,
                "exploitation_confirmed": exploitation_confirmed,
            },
        ))
        return evidence
