from sqlalchemy import func, select

from app.models.entities import ComplianceControl, FindingStatus, Vulnerability, VulnerabilityControl


async def framework_score_breakdown(session, framework_id) -> dict:
    controls = (
        await session.execute(select(ComplianceControl).where(ComplianceControl.framework_id == framework_id))
    ).scalars().all()
    control_ids = [control.id for control in controls]
    total_counts: dict[str, int] = {}
    open_counts: dict[str, int] = {}

    if control_ids:
        total_counts = {
            str(control_id): count
            for control_id, count in (
                await session.execute(
                    select(
                        VulnerabilityControl.control_id,
                        func.count(VulnerabilityControl.id),
                    )
                    .where(VulnerabilityControl.control_id.in_(control_ids))
                    .group_by(VulnerabilityControl.control_id)
                )
            ).all()
        }
        open_counts = {
            str(control_id): count
            for control_id, count in (
                await session.execute(
                    select(
                        VulnerabilityControl.control_id,
                        func.count(VulnerabilityControl.id),
                    )
                    .join(Vulnerability, Vulnerability.id == VulnerabilityControl.vulnerability_id)
                    .where(
                        VulnerabilityControl.control_id.in_(control_ids),
                        Vulnerability.status.not_in([FindingStatus.closed, FindingStatus.verified]),
                    )
                    .group_by(VulnerabilityControl.control_id)
                )
            ).all()
        }

    control_breakdown = []
    for control in controls:
        total_findings = total_counts.get(str(control.id), 0)
        open_findings = open_counts.get(str(control.id), 0)
        control_breakdown.append(
            {
                "control_id": control.control_id,
                "title": control.title,
                "total_findings": total_findings,
                "open_findings": open_findings,
                "passing": open_findings == 0,
            }
        )

    total_controls = len(control_breakdown)
    failing_controls = sum(1 for control in control_breakdown if not control["passing"])
    passing_controls = total_controls - failing_controls
    score = int((passing_controls / total_controls) * 100) if total_controls else 100
    return {
        "score": score,
        "total_controls": total_controls,
        "passing_controls": passing_controls,
        "failing_controls": failing_controls,
        "controls": control_breakdown,
    }
