import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.models.entities import Asset, CrownJewelTier, NetworkZone
from app.routes.scope import AssetCrownJewelPatch, create_asset, set_business_context, set_crown_jewel
from app.schemas.assets import AssetCreate, BusinessContextCreate
from app.services.scope_service import (
    derive_applicable_frameworks,
    ensure_default_crown_jewel_tiers,
    normalize_asset_business_context,
    resolve_zone_id_for_ip,
)


class FakeScalarResult:
    def __init__(self, rows):
        self.rows = list(rows)

    def scalars(self):
        return self

    def all(self):
        return list(self.rows)


class ScopeSession:
    def __init__(self, zones=None, asset=None, tiers=None):
        self.zones = list(zones or [])
        self.asset = asset
        self.tiers = list(tiers or [])
        self.added = []
        self.committed = False
        self.info = {"tenant_id": getattr(asset, "tenant_id", None)}

    async def execute(self, statement):
        entity = statement.column_descriptions[0]["entity"]
        if entity is NetworkZone:
            return FakeScalarResult(self.zones)
        if entity is CrownJewelTier:
            return FakeScalarResult(self.tiers)
        raise AssertionError(f"Unexpected entity: {entity}")

    async def get(self, model, key):
        if model is Asset and self.asset is not None and str(self.asset.id) == str(key):
            return self.asset
        if model is CrownJewelTier:
            for tier in self.tiers:
                if str(getattr(tier, "id", "")) == str(key):
                    return tier
        return None

    def add(self, obj):
        self.added.append(obj)
        if isinstance(obj, CrownJewelTier):
            self.tiers.append(obj)

    async def flush(self):
        return None

    async def commit(self):
        self.committed = True


class FakeRedis:
    def __init__(self):
        self.deleted = []

    async def delete(self, *keys):
        self.deleted.extend(keys)


def test_resolve_zone_id_prefers_most_specific_cidr():
    broad = SimpleNamespace(id=uuid4(), cidr="10.0.0.0/16")
    narrow = SimpleNamespace(id=uuid4(), cidr="10.0.1.0/24")

    matched = resolve_zone_id_for_ip("10.0.1.8", [broad, narrow])

    assert matched == narrow.id


def test_derive_applicable_frameworks_from_industry():
    frameworks = derive_applicable_frameworks("Healthcare")

    assert "HIPAA" in frameworks
    assert "NIST CSF 2.0" in frameworks


def test_ensure_default_crown_jewel_tiers_creates_three_tiers_with_attributes():
    session = ScopeSession()

    asyncio.run(ensure_default_crown_jewel_tiers(session))

    assert len(session.tiers) == 3
    assert {tier.name for tier in session.tiers} == {"tier_1", "tier_2", "tier_3"}
    tier_1 = next(tier for tier in session.tiers if tier.name == "tier_1")
    assert tier_1.revenue_tier == ">100M"
    assert tier_1.data_sensitivity == "restricted"


def test_create_asset_auto_assigns_zone_when_zone_not_provided():
    zone = SimpleNamespace(id=uuid4(), cidr="10.10.0.0/24")
    session = ScopeSession(zones=[zone])

    response = asyncio.run(
        create_asset(
            AssetCreate(hostname="web-1", ip_address="10.10.0.9", criticality_score=60),
            session=session,
        )
    )

    created_asset = next(item for item in session.added if isinstance(item, Asset))
    assert created_asset.zone_id == zone.id
    assert response.message


def test_set_business_context_auto_populates_regulatory_frameworks():
    asset = Asset(
        id=uuid4(),
        tenant_id=uuid4(),
        hostname="db-1",
        ip_address="10.0.0.5",
        criticality_score=80,
        business_context={"attack_path_score": 85, "is_crown_jewel": True},
    )
    session = ScopeSession(asset=asset)

    asyncio.run(
        set_business_context(
            BusinessContextCreate(
                asset_id=asset.id,
                business_context={"industry_sector": "Financial Services", "annual_revenue": ">100M"},
            ),
            session=session,
            redis=FakeRedis(),
        )
    )

    assert "NYDFS 23 NYCRR 500" in asset.business_context["applicable_regulatory_frameworks"]
    assert "PCI-DSS 4.0" in asset.business_context["applicable_regulatory_frameworks"]
    assert asset.business_context["attack_path_score"] == 85
    assert asset.business_context["is_crown_jewel"] is True


def test_normalize_asset_business_context_marks_tiered_asset_as_crown_jewel():
    asset = SimpleNamespace(
        crown_jewel_tier_id=uuid4(),
        business_context={"is_crown_jewel": False, "attack_path_score": 85},
    )

    context = normalize_asset_business_context(asset, crown_jewel_tier_name="tier_1")

    assert context["is_crown_jewel"] is True
    assert context["crown_jewel_tier"] == "tier_1"
    assert context["attack_path_score"] == 85


def test_set_crown_jewel_syncs_business_context_flag_and_tier():
    asset = Asset(
        id=uuid4(),
        tenant_id=uuid4(),
        hostname="db-1",
        ip_address="10.0.0.5",
        criticality_score=80,
        business_context={"is_crown_jewel": False, "attack_path_score": 85},
    )
    tier = SimpleNamespace(id=uuid4(), name="tier_1")
    session = ScopeSession(asset=asset, tiers=[tier])
    redis = FakeRedis()

    response = asyncio.run(
        set_crown_jewel(
            str(asset.id),
            AssetCrownJewelPatch(crown_jewel_tier_id=str(tier.id)),
            session=session,
            redis=redis,
        )
    )

    assert asset.crown_jewel_tier_id == tier.id
    assert asset.business_context["is_crown_jewel"] is True
    assert asset.business_context["crown_jewel_tier"] == "tier_1"
    assert response["crown_jewel_tier"] == "tier_1"
    assert redis.deleted
