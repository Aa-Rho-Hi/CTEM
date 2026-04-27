from sqlalchemy import select

from app.models.entities import ThreatActorCampaign, VulnerabilityCampaignMapping


class ThreatActorMapper:
    async def apply_campaign_bonus(self, session, vulnerability, industry_sector: str | None = None) -> int:
        campaigns = (await session.execute(select(ThreatActorCampaign))).scalars().all()
        bonus = 0
        for campaign in campaigns:
            campaign_status = str((campaign.metadata_json or {}).get("status", "active")).lower()
            if campaign_status != "active":
                continue
            ttp_match = campaign.mitre_attack_ttp and campaign.mitre_attack_ttp == vulnerability.mitre_attack_ttp
            industry_match = industry_sector and campaign.industry_sector and campaign.industry_sector == industry_sector
            if ttp_match and industry_match:
                session.add(
                    VulnerabilityCampaignMapping(
                        tenant_id=vulnerability.tenant_id,
                        vulnerability_id=vulnerability.id,
                        campaign_id=campaign.id,
                    )
                )
                vulnerability.matched_campaign_id = campaign.id
                bonus = 10
                break
        vulnerability.risk_score = min(100, vulnerability.risk_score + bonus)
        await session.flush()
        return bonus
