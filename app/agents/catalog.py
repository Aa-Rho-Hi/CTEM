from app.agents.base import BaseAgent as _BaseAgent
from app.agents.implementations import StandardAgent

PLATFORM_TOOLS = [
    "nmap",
    "nessus",
    "qualys",
    "checkmarx",
    "sonarqube",
    "rapid7",
    "veracode",
    "burp_suite",
    "snyk",
    "nvd_lookup",
    "attack_graph_query",
    "graphrag_query",
    "tanium_patch",
    "servicenow_ticket",
    "jira_ticket",
    "compliance_mapper",
]

AGENT_CATALOGUE = {
    "discovery_agent": {"tools": ["nmap", "nessus", "qualys"], "default_ceiling": 70},
    "sast_agent": {"tools": ["checkmarx", "sonarqube", "veracode"], "default_ceiling": 75},
    "enrichment_agent": {"tools": ["nvd_lookup", "attack_graph_query"], "default_ceiling": 80},
    "pt_agent": {"tools": ["nmap", "burp_suite", "snyk"], "default_ceiling": 85},
    "remediation_agent": {"tools": ["tanium_patch", "servicenow_ticket", "jira_ticket"], "default_ceiling": 90},
    "compliance_agent": {"tools": ["compliance_mapper", "graphrag_query"], "default_ceiling": 75},
}

AGENT_CLASS_NAMES = [
    "AttackPathAgent",
    "ExposureTriageAgent",
    "PatchPlanningAgent",
    "ConfigHardeningAgent",
    "CodeFixAgent",
    "ManualPlaybookAgent",
    "ApprovalNarrativeAgent",
    "BlastRadiusAgent",
    "ChangeWindowAgent",
    "ServiceNowAgent",
    "JiraAgent",
    "TaniumAgent",
    "SplunkAgent",
    "NessusAgent",
    "QualysAgent",
    "OpenVASAgent",
    "NmapAgent",
    "BurpAgent",
    "ComplianceMappingAgent",
    "PCIAdvisorAgent",
    "HIPAAAdvisorAgent",
    "CMMCAdvisorAgent",
    "SOCAdvisorAgent",
    "GDPRAdvisorAgent",
    "CCPAAdvisorAgent",
    "NYDFSAdvisorAgent",
    "CRIAdvisorAgent",
    "ROEGuardAgent",
    "KillSwitchGuardAgent",
    "TenantBoundaryAgent",
    "FalsePositiveAgent",
    "VerificationAgent",
]


class DiscoveryAgent(StandardAgent):
    """Scans and maps the attack surface using network/vuln tools."""


class SASTAgent(StandardAgent):
    """Performs static analysis to surface code-level vulnerabilities."""


class EnrichmentAgent(StandardAgent):
    """Enriches findings with CVE data and attack-graph context."""


class PenTestAgent(StandardAgent):
    """Plans and executes controlled penetration-test probes."""


class RemediationAgent(StandardAgent):
    """Prioritises and dispatches patch/ticket remediation actions."""


class ComplianceAgent(StandardAgent):
    """Maps the graph posture against compliance frameworks."""


_TYPE_TO_CLASS: dict[str, type[_BaseAgent]] = {
    "discovery_agent": DiscoveryAgent,
    "sast_agent": SASTAgent,
    "enrichment_agent": EnrichmentAgent,
    "pt_agent": PenTestAgent,
    "remediation_agent": RemediationAgent,
    "compliance_agent": ComplianceAgent,
}


class AgentFactory:
    @staticmethod
    def create(
        agent_type: str,
        tenant_id: str,
        tool_whitelist: list[str] | None = None,
        safety_ceiling: int | None = None,
        agent_id: str | None = None,
    ) -> "_BaseAgent":
        from uuid import uuid4

        spec = AGENT_CATALOGUE.get(agent_type)
        if spec is None:
            raise ValueError(
                f"Unknown agent type: {agent_type}. Valid types: {list(AGENT_CATALOGUE.keys())}"
            )
        tools = tool_whitelist or spec["tools"]
        invalid = [tool for tool in tools if tool not in PLATFORM_TOOLS]
        if invalid:
            raise ValueError(f"Invalid tools: {invalid}. Must be from PLATFORM_TOOLS.")
        cls = _TYPE_TO_CLASS[agent_type]
        return cls(
            tenant_id=tenant_id,
            tool_whitelist=tools,
            safety_ceiling=safety_ceiling or spec["default_ceiling"],
            agent_id=agent_id or str(uuid4()),
        )

    @staticmethod
    async def load_from_db(session, agent_id: str) -> tuple["_BaseAgent", object]:
        """Load a persisted Agent row from DB and return (impl_instance, orm_row)."""
        from app.models.entities import Agent as AgentModel

        agent_row = await session.get(AgentModel, agent_id)
        if agent_row is None:
            raise ValueError(f"Agent {agent_id} not found.")
        if agent_row.status == "decommissioned":
            raise ValueError(f"Agent {agent_id} is decommissioned and cannot be loaded.")
        impl = AgentFactory.create(
            agent_type=agent_row.config_json.get("agent_type"),
            tenant_id=str(agent_row.tenant_id),
            tool_whitelist=agent_row.tool_whitelist,
            safety_ceiling=agent_row.safety_ceiling,
            agent_id=str(agent_row.id),
        )
        return impl, agent_row
