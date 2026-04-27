import base64

import httpx
from sqlalchemy import select

from app.config import get_settings
from app.models.entities import Integration, Remediation
from app.schemas.common import AuditLogCreate
from app.services.audit_writer import AuditWriter


class ITSMService:
    def __init__(self):
        self.settings = get_settings()

    async def create_ticket(self, session, finding, remediation_plan, tenant_id: str) -> dict:
        preferred = (
            await session.execute(select(Integration).where(Integration.integration_type.in_(["servicenow", "jira"])))
        ).scalars().first()
        provider = preferred.integration_type if preferred else "servicenow"
        config = preferred.config_json if preferred else {}
        if self.settings.environment == "development":
            import random
            ticket_num = random.randint(10000, 99999)
            payload = (
                {"sys_id": f"snow-{ticket_num}", "number": f"INC{ticket_num:07d}", "state": "New"}
                if provider == "servicenow"
                else {"id": str(ticket_num), "key": f"SEC-{ticket_num}", "self": f"http://mock-jira/rest/api/2/issue/{ticket_num}"}
            )
        else:
            payload = await (self._create_servicenow(finding, remediation_plan, config) if provider == "servicenow" else self._create_jira(finding, remediation_plan, config))
        remediation_plan.ticket_id = payload.get("number") or payload.get("key") or payload.get("id")
        remediation_plan.ticket_url = payload.get("self") or payload.get("sys_id")
        await AuditWriter().write(
            session,
            tenant_id,
            AuditLogCreate(
                action="itsm_ticket_created",
                resource_type="remediation",
                resource_id=str(remediation_plan.id),
                details={"ticket_id": remediation_plan.ticket_id, "finding_id": str(finding.id)},
            ),
        )
        await session.commit()
        return payload

    async def _create_servicenow(self, finding, remediation_plan, config: dict):
        assignment_group = config.get("assignment_group", "Security Operations")
        assigned_to = config.get("assignee") or config.get("assigned_to")
        auth = base64.b64encode(f"{self.settings.servicenow_user}:{self.settings.servicenow_pass}".encode()).decode()
        body = {
            "short_description": f"[ATLAS-CTEM] {finding.cve_id} on {finding.asset_id}",
            "description": remediation_plan.risk_narrative,
            "urgency": "1" if finding.severity == "Critical" else "2",
            "assignment_group": assignment_group,
            "u_risk_score": str(finding.risk_score),
            "u_finding_id": str(finding.id),
        }
        if assigned_to:
            body["assigned_to"] = assigned_to
        async with httpx.AsyncClient(timeout=10.0, verify=True) as client:
            response = await client.post(
                f"{self.settings.servicenow_url}/api/now/table/incident",
                headers={"Authorization": f"Basic {auth}"},
                json=body,
            )
            response.raise_for_status()
            return response.json()["result"]

    async def _create_jira(self, finding, remediation_plan, config: dict):
        project_key = config.get("project_key", "SEC")
        assignee = config.get("assignee")
        fields = {
            "project": {"key": project_key},
            "summary": f"[CTEM] {finding.cve_id} — {finding.asset_id}",
            "description": remediation_plan.risk_narrative,
            "issuetype": {"name": "Bug"},
            "priority": {"name": finding.severity},
            "labels": ["atlas-ctem", finding.cve_id],
        }
        if isinstance(assignee, dict):
            fields["assignee"] = assignee
        elif assignee:
            fields["assignee"] = {"name": assignee}
        async with httpx.AsyncClient(timeout=10.0, verify=True) as client:
            response = await client.post(
                f"{self.settings.jira_url}/rest/api/2/issue",
                headers={"Authorization": f"Bearer {self.settings.jira_api_key}"},
                json={"fields": fields},
            )
            response.raise_for_status()
            return response.json()
