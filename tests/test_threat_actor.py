import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.models.entities import ThreatActorCampaign, VulnerabilityCampaignMapping
from app.services.threat_actor import ThreatActorMapper


class FakeScalarResult:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self.rows)


class FakeSession:
    def __init__(self, campaigns):
        self.campaigns = campaigns
        self.added = []

    async def execute(self, statement):
        entity = statement.column_descriptions[0]["entity"]
        if entity is ThreatActorCampaign:
            return FakeScalarResult(self.campaigns)
        raise AssertionError(f"Unexpected entity: {entity}")

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        return None


def test_only_active_campaigns_increase_risk():
    active_campaign = SimpleNamespace(
        id=uuid4(),
        industry_sector="finance",
        mitre_attack_ttp="T1190",
        metadata_json={"status": "active"},
    )
    inactive_campaign = SimpleNamespace(
        id=uuid4(),
        industry_sector="finance",
        mitre_attack_ttp="T1190",
        metadata_json={"status": "inactive"},
    )
    vulnerability = SimpleNamespace(
        id=uuid4(),
        tenant_id=uuid4(),
        mitre_attack_ttp="T1190",
        risk_score=70,
        matched_campaign_id=None,
    )
    session = FakeSession([inactive_campaign, active_campaign])

    bonus = asyncio.run(ThreatActorMapper().apply_campaign_bonus(session, vulnerability, industry_sector="finance"))

    assert bonus == 10
    assert vulnerability.risk_score == 80
    assert vulnerability.matched_campaign_id == active_campaign.id
    assert any(isinstance(item, VulnerabilityCampaignMapping) for item in session.added)
