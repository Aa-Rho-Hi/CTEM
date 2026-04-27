from typing import Any

from app.agents.base import BaseAgent


class StandardAgent(BaseAgent):
    """Standard agent contract for all concrete agent classes."""

    def __init__(
        self,
        tenant_id,
        tool_whitelist,
        safety_ceiling,
        agent_id,
        confidence_score: int = 85,
    ):
        super().__init__(
            tenant_id=tenant_id,
            tool_whitelist=tool_whitelist,
            safety_ceiling=safety_ceiling,
            agent_id=agent_id,
            confidence_score=confidence_score,
        )

    async def run(
        self,
        goal: str,
        session=None,
        tenant_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        try:
            return await super().run(
                goal=goal,
                session=session,
                tenant_id=tenant_id,
                metadata=metadata,
            )
        except Exception as exc:
            if session is not None and self.agent_id:
                active_tenant_id = tenant_id or str(self.tenant_id)
                await self._log_decision(
                    session=session,
                    tenant_id=active_tenant_id,
                    goal=goal,
                    reasoning=metadata or {"summary": "agent execution failed"},
                    decision="agent_error",
                    confidence=0,
                    outcome=str(exc),
                )
            raise


def _make_standard_agent_class(name: str):
    return type(name, (StandardAgent,), {})


AttackPathAgent = _make_standard_agent_class("AttackPathAgent")
ExposureTriageAgent = _make_standard_agent_class("ExposureTriageAgent")
PatchPlanningAgent = _make_standard_agent_class("PatchPlanningAgent")
ConfigHardeningAgent = _make_standard_agent_class("ConfigHardeningAgent")
CodeFixAgent = _make_standard_agent_class("CodeFixAgent")
ManualPlaybookAgent = _make_standard_agent_class("ManualPlaybookAgent")
ApprovalNarrativeAgent = _make_standard_agent_class("ApprovalNarrativeAgent")
BlastRadiusAgent = _make_standard_agent_class("BlastRadiusAgent")
ChangeWindowAgent = _make_standard_agent_class("ChangeWindowAgent")
ServiceNowAgent = _make_standard_agent_class("ServiceNowAgent")
JiraAgent = _make_standard_agent_class("JiraAgent")
TaniumAgent = _make_standard_agent_class("TaniumAgent")
SplunkAgent = _make_standard_agent_class("SplunkAgent")
NessusAgent = _make_standard_agent_class("NessusAgent")
QualysAgent = _make_standard_agent_class("QualysAgent")
OpenVASAgent = _make_standard_agent_class("OpenVASAgent")
NmapAgent = _make_standard_agent_class("NmapAgent")
BurpAgent = _make_standard_agent_class("BurpAgent")
ComplianceMappingAgent = _make_standard_agent_class("ComplianceMappingAgent")
PCIAdvisorAgent = _make_standard_agent_class("PCIAdvisorAgent")
HIPAAAdvisorAgent = _make_standard_agent_class("HIPAAAdvisorAgent")
CMMCAdvisorAgent = _make_standard_agent_class("CMMCAdvisorAgent")
SOCAdvisorAgent = _make_standard_agent_class("SOCAdvisorAgent")
GDPRAdvisorAgent = _make_standard_agent_class("GDPRAdvisorAgent")
CCPAAdvisorAgent = _make_standard_agent_class("CCPAAdvisorAgent")
NYDFSAdvisorAgent = _make_standard_agent_class("NYDFSAdvisorAgent")
CRIAdvisorAgent = _make_standard_agent_class("CRIAdvisorAgent")
ROEGuardAgent = _make_standard_agent_class("ROEGuardAgent")
KillSwitchGuardAgent = _make_standard_agent_class("KillSwitchGuardAgent")
TenantBoundaryAgent = _make_standard_agent_class("TenantBoundaryAgent")
FalsePositiveAgent = _make_standard_agent_class("FalsePositiveAgent")
VerificationAgent = _make_standard_agent_class("VerificationAgent")
