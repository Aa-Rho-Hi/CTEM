from app.models.entities import Asset


class AssetService:
    async def get(self, session, asset_id: str, tenant_id: str) -> Asset:
        asset = await session.get(Asset, asset_id)
        if asset is None:
            raise ValueError(f"Asset {asset_id} not found")
        return asset
