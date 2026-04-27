import ipaddress

from sqlalchemy import select

from app.models.entities import CrownJewelTier

DEFAULT_CROWN_JEWEL_TIERS = (
    {
        "name": "tier_1",
        "multiplier": 3,
        "revenue_tier": ">100M",
        "data_sensitivity": "restricted",
    },
    {
        "name": "tier_2",
        "multiplier": 2,
        "revenue_tier": "10M-100M",
        "data_sensitivity": "confidential",
    },
    {
        "name": "tier_3",
        "multiplier": 1,
        "revenue_tier": "1M-10M",
        "data_sensitivity": "internal",
    },
)

INDUSTRY_FRAMEWORK_MAP = {
    "finance": ["NIST CSF 2.0", "PCI-DSS 4.0", "SOC 2 Type II", "NYDFS 23 NYCRR 500"],
    "financial services": ["NIST CSF 2.0", "PCI-DSS 4.0", "SOC 2 Type II", "NYDFS 23 NYCRR 500"],
    "banking": ["NIST CSF 2.0", "PCI-DSS 4.0", "SOC 2 Type II", "NYDFS 23 NYCRR 500"],
    "healthcare": ["NIST CSF 2.0", "HIPAA", "SOC 2 Type II"],
    "retail": ["NIST CSF 2.0", "PCI-DSS 4.0", "SOC 2 Type II", "CCPA"],
    "e-commerce": ["NIST CSF 2.0", "PCI-DSS 4.0", "SOC 2 Type II", "CCPA"],
    "saas": ["NIST CSF 2.0", "SOC 2 Type II", "ISO 27001:2022", "GDPR"],
    "technology": ["NIST CSF 2.0", "SOC 2 Type II", "ISO 27001:2022", "GDPR"],
    "government": ["NIST CSF 2.0", "CMMC Level 2", "CRI Profile 2.0"],
    "public sector": ["NIST CSF 2.0", "CMMC Level 2", "CRI Profile 2.0"],
    "manufacturing": ["NIST CSF 2.0", "CMMC Level 2", "ISO 27001:2022"],
    "energy": ["NIST CSF 2.0", "CRI Profile 2.0", "ISO 27001:2022"],
    "utilities": ["NIST CSF 2.0", "CRI Profile 2.0", "ISO 27001:2022"],
    "education": ["NIST CSF 2.0", "SOC 2 Type II", "FERPA"],
}


def derive_applicable_frameworks(industry_sector: str | None) -> list[str]:
    if not industry_sector:
        return ["NIST CSF 2.0", "SOC 2 Type II"]

    normalized = industry_sector.strip().lower()
    if normalized in INDUSTRY_FRAMEWORK_MAP:
        return list(INDUSTRY_FRAMEWORK_MAP[normalized])

    for key, frameworks in INDUSTRY_FRAMEWORK_MAP.items():
        if key in normalized or normalized in key:
            return list(frameworks)

    return ["NIST CSF 2.0", "SOC 2 Type II"]


def normalize_asset_business_context(
    asset,
    *,
    base_context: dict | None = None,
    crown_jewel_tier_name: str | None = None,
    is_crown_jewel: bool | None = None,
) -> dict:
    context = dict(base_context if base_context is not None else (getattr(asset, "business_context", None) or {}))
    if is_crown_jewel is None:
        is_crown_jewel = bool(
            getattr(asset, "crown_jewel_tier_id", None)
            or context.get("is_crown_jewel")
        )
    context["is_crown_jewel"] = bool(is_crown_jewel)
    if crown_jewel_tier_name:
        context["crown_jewel_tier"] = crown_jewel_tier_name
    else:
        context.pop("crown_jewel_tier", None)
    return context


def resolve_zone_id_for_ip(ip_address: str, zones) -> object | None:
    target_ip = ipaddress.ip_address(ip_address)
    matched_zone = None
    matched_prefix = -1

    for zone in zones:
        network = ipaddress.ip_network(zone.cidr, strict=False)
        if target_ip not in network:
            continue
        if network.prefixlen > matched_prefix:
            matched_zone = zone
            matched_prefix = network.prefixlen

    return matched_zone.id if matched_zone is not None else None


async def ensure_default_crown_jewel_tiers(session):
    existing = {
        tier.name: tier
        for tier in (await session.execute(select(CrownJewelTier))).scalars().all()
    }
    created_or_updated = []
    for definition in DEFAULT_CROWN_JEWEL_TIERS:
        tier = existing.get(definition["name"])
        if tier is None:
            tier = CrownJewelTier(**definition)
            session.add(tier)
            created_or_updated.append(tier)
            continue
        tier.multiplier = definition["multiplier"]
        tier.revenue_tier = definition["revenue_tier"]
        tier.data_sensitivity = definition["data_sensitivity"]
        created_or_updated.append(tier)
    await session.flush()
    return created_or_updated
