from dataclasses import dataclass
from datetime import datetime, timezone

from app.models.entities import Asset, DryRunOutput, Remediation, Vulnerability


@dataclass
class DryRunResult:
    remediation_id: str
    fix_type: str
    simulated_actions: dict
    estimated_duration_minutes: int
    requires_downtime: bool
    services_affected: list[str]
    generated_at: str


class DryRunService:
    async def generate(self, session, remediation_id: str, tenant_id: str) -> DryRunResult:
        remediation = await session.get(Remediation, remediation_id)
        if remediation is None:
            raise ValueError("Remediation not found.")
        finding = await session.get(Vulnerability, remediation.vulnerability_id)
        asset = await session.get(Asset, finding.asset_id) if finding and finding.asset_id else None
        fix_type = remediation.fix_type
        if fix_type == "patch":
            output = {
                "action": "apt upgrade vulnerable-package",
                "current_version": "1.0.0",
                "target_version": "1.0.1",
                "services_to_restart": [asset.hostname if asset else "service"],
            }
            duration = 30
            services = output["services_to_restart"]
        elif fix_type == "configuration":
            output = {
                "action": "set secure_mode=true",
                "current_value": "false",
                "new_value": "true",
                "config_file": "/etc/app/config.yml",
            }
            duration = 20
            services = [asset.hostname if asset else "service"]
        elif fix_type == "code":
            output = {
                "action": "deploy build abc1234",
                "files_changed": ["app/security.py"],
                "test_suite": "must pass before deploy",
            }
            duration = 60
            services = [asset.hostname if asset else "web_app"]
        else:
            output = {
                "action": "manual review required",
                "steps": remediation.fix_steps,
            }
            duration = 45
            services = [asset.hostname if asset else "manual"]
        result = DryRunResult(
            remediation_id=remediation_id,
            fix_type=fix_type,
            simulated_actions=output,
            estimated_duration_minutes=duration,
            requires_downtime=remediation.requires_downtime,
            services_affected=services,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
        record = DryRunOutput(
            tenant_id=tenant_id,
            remediation_id=remediation.id,
            fix_type=fix_type,
            estimated_duration_minutes=duration,
            requires_downtime=remediation.requires_downtime,
            services_affected=services,
            output_json=output,
        )
        session.add(record)
        await session.flush()
        return result
