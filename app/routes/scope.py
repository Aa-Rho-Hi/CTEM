from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from app.core.security import require_roles
from app.dependencies import get_redis, get_tenant_session
from app.models.entities import Asset, CrownJewelTier, NetworkZone
from app.schemas.assets import AssetCreate, BusinessContextCreate, ChangeWindowCreate, ZoneCreate
from app.schemas.common import MessageResponse
from app.services.scope_service import (
    derive_applicable_frameworks,
    ensure_default_crown_jewel_tiers,
    normalize_asset_business_context,
    resolve_zone_id_for_ip,
)

router = APIRouter(prefix="/scope", tags=["scope"])


def _serialize_zone(zone: NetworkZone) -> dict:
    days = zone.change_windows.get("change_window_days", [])
    start = zone.change_windows.get("change_window_start")
    end = zone.change_windows.get("change_window_end")
    change_window = None
    if days and start and end:
        change_window = f"{','.join(map(str, days))} {start}-{end}"
    return {
        "id": str(zone.id),
        "name": zone.name,
        "cidr": zone.cidr,
        "pci": zone.pci,
        "hipaa": zone.hipaa,
        "change_window": change_window,
        "change_windows": zone.change_windows or {},
    }


def _serialize_asset(asset: Asset, zone_name: str | None = None, tier_name: str | None = None) -> dict:
    return {
        "id": str(asset.id),
        "ip_address": asset.ip_address,
        "hostname": asset.hostname,
        "zone_id": str(asset.zone_id) if asset.zone_id else None,
        "zone_name": zone_name,
        "criticality_score": asset.criticality_score,
        "crown_jewel_tier": tier_name,
        "crown_jewel_tier_id": str(asset.crown_jewel_tier_id) if asset.crown_jewel_tier_id else None,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
        "business_context": normalize_asset_business_context(asset, crown_jewel_tier_name=tier_name),
    }


async def _invalidate_attack_surface_cache(redis, tenant_id: str | None) -> None:
    if tenant_id is None:
        return
    try:
        await redis.delete(
            f"attack_surface:{tenant_id}",
            f"attack_surface:v2:{tenant_id}",
            f"attack_surface:v3:{tenant_id}",
        )
    except Exception:
        pass


def _session_tenant_id(session) -> str | None:
    info = getattr(session, "info", None) or {}
    tenant_id = info.get("tenant_id")
    return str(tenant_id) if tenant_id else None


@router.get("/zones", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor", "client_viewer"))])
async def list_zones(session=Depends(get_tenant_session)):
    zones = (await session.execute(select(NetworkZone).order_by(NetworkZone.created_at.desc()))).scalars().all()
    return {"items": [_serialize_zone(zone) for zone in zones]}


@router.post("/zones", response_model=MessageResponse, dependencies=[Depends(require_roles("super_admin", "security_analyst"))])
async def create_zone(payload: ZoneCreate, session=Depends(get_tenant_session)) -> MessageResponse:
    zone = NetworkZone(**payload.model_dump())
    session.add(zone)
    await session.flush()

    zones = (await session.execute(select(NetworkZone))).scalars().all()
    assets = (await session.execute(select(Asset))).scalars().all()
    for asset in assets:
        asset.zone_id = resolve_zone_id_for_ip(asset.ip_address, zones)

    await session.commit()
    return MessageResponse(message=str(zone.id))


@router.get("/crown-jewel-tiers", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor", "client_viewer"))])
async def list_crown_jewel_tiers(session=Depends(get_tenant_session)):
    await ensure_default_crown_jewel_tiers(session)
    tiers = (await session.execute(select(CrownJewelTier).order_by(CrownJewelTier.multiplier.desc()))).scalars().all()
    await session.commit()
    return {
        "items": [
            {
                "id": str(t.id),
                "name": t.name,
                "multiplier": t.multiplier,
                "revenue_tier": t.revenue_tier,
                "data_sensitivity": t.data_sensitivity,
            }
            for t in tiers
        ]
    }


@router.get("/assets", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor", "client_viewer"))])
async def list_assets(
    limit: int | None = Query(default=None, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session=Depends(get_tenant_session),
):
    zones = (await session.execute(select(NetworkZone))).scalars().all()
    zone_map = {str(zone.id): zone.name for zone in zones}
    tiers = (await session.execute(select(CrownJewelTier))).scalars().all()
    tier_map = {str(t.id): t.name for t in tiers}
    total = (await session.execute(select(func.count()).select_from(Asset))).scalar_one()
    statement = select(Asset).order_by(Asset.created_at.desc())
    if limit is not None:
        statement = statement.limit(limit).offset(offset)
    assets = (await session.execute(statement)).scalars().all()
    return {
        "items": [
            _serialize_asset(
                asset,
                zone_map.get(str(asset.zone_id)) if asset.zone_id else None,
                tier_map.get(str(asset.crown_jewel_tier_id)) if asset.crown_jewel_tier_id else None,
            )
            for asset in assets
        ],
        "limit": limit,
        "offset": offset,
        "total": total,
    }


@router.post("/assets", response_model=MessageResponse, dependencies=[Depends(require_roles("super_admin", "security_analyst"))])
async def create_asset(payload: AssetCreate, session=Depends(get_tenant_session)) -> MessageResponse:
    asset_data = payload.model_dump()
    if asset_data.get("zone_id") is None:
        zones = (await session.execute(select(NetworkZone))).scalars().all()
        asset_data["zone_id"] = resolve_zone_id_for_ip(payload.ip_address, zones)
    asset = Asset(**asset_data)
    session.add(asset)
    await session.commit()
    return MessageResponse(message=str(asset.id))


@router.get("/business-context", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor", "client_viewer"))])
async def get_business_context(
    asset_id: str | None = Query(default=None),
    session=Depends(get_tenant_session),
):
    asset = None
    if asset_id:
        asset = await session.get(Asset, asset_id)
    else:
        asset = (
            await session.execute(select(Asset).order_by(Asset.created_at.desc()))
        ).scalars().first()
    if asset is None:
        return {
            "asset_id": None,
            "business_context": {
                "industry_sector": "",
                "annual_revenue": "",
                "applicable_regulatory_frameworks": [],
            },
        }
    context = asset.business_context or {}
    return {
        "asset_id": str(asset.id),
        "business_context": {
            "industry_sector": context.get("industry_sector", ""),
            "annual_revenue": context.get("annual_revenue", ""),
            "applicable_regulatory_frameworks": context.get("applicable_regulatory_frameworks", []),
        },
    }


@router.post("/business-context", response_model=MessageResponse, dependencies=[Depends(require_roles("super_admin", "security_analyst"))])
async def set_business_context(payload: BusinessContextCreate, session=Depends(get_tenant_session), redis=Depends(get_redis)) -> MessageResponse:
    asset = await session.get(Asset, payload.asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    tier_name = None
    if asset.crown_jewel_tier_id:
        tier = await session.get(CrownJewelTier, asset.crown_jewel_tier_id)
        tier_name = tier.name if tier is not None else None
    updated_context = dict(asset.business_context or {})
    updated_context.update(payload.business_context)
    updated_context["applicable_regulatory_frameworks"] = derive_applicable_frameworks(
        updated_context.get("industry_sector")
    )
    asset.business_context = normalize_asset_business_context(
        asset,
        base_context=updated_context,
        crown_jewel_tier_name=tier_name,
    )
    await session.commit()
    await _invalidate_attack_surface_cache(redis, _session_tenant_id(session))
    return MessageResponse(message="updated")


class AssetCrownJewelPatch(BaseModel):
    crown_jewel_tier_id: str | None


@router.patch("/assets/{asset_id}/crown-jewel", dependencies=[Depends(require_roles("super_admin", "security_analyst"))])
async def set_crown_jewel(asset_id: str, payload: AssetCrownJewelPatch, session=Depends(get_tenant_session), redis=Depends(get_redis)):
    asset = await session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    updated_context = dict(asset.business_context or {})
    if payload.crown_jewel_tier_id:
        tier = await session.get(CrownJewelTier, payload.crown_jewel_tier_id)
        if tier is None:
            raise HTTPException(status_code=404, detail="Crown jewel tier not found.")
        asset.crown_jewel_tier_id = tier.id
        tier_name = tier.name
    else:
        asset.crown_jewel_tier_id = None
        tier_name = None
    asset.business_context = normalize_asset_business_context(
        asset,
        base_context=updated_context,
        crown_jewel_tier_name=tier_name,
        is_crown_jewel=bool(payload.crown_jewel_tier_id),
    )
    await session.commit()
    await _invalidate_attack_surface_cache(redis, _session_tenant_id(session))
    return {"id": str(asset.id), "crown_jewel_tier": tier_name}


@router.post("/change-windows", response_model=MessageResponse, dependencies=[Depends(require_roles("super_admin", "security_analyst"))])
async def set_change_windows(payload: ChangeWindowCreate, session=Depends(get_tenant_session)) -> MessageResponse:
    zone = await session.get(NetworkZone, payload.zone_id)
    if zone is None:
        raise HTTPException(status_code=404, detail="Zone not found.")
    zone.change_windows = payload.change_windows
    await session.commit()
    return MessageResponse(message="updated")
