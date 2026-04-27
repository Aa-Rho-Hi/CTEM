from datetime import datetime, timezone

from app.models.entities import Asset, NetworkZone
from app.services.errors import ChangeWindowBlockedError


class ChangeWindowService:
    def __init__(self, now_provider=None):
        self.now_provider = now_provider or (lambda: datetime.now(timezone.utc))

    async def is_execution_allowed(self, session, asset_id: str, tenant_id: str) -> bool:
        asset = await session.get(Asset, asset_id)
        if asset is None or asset.zone_id is None:
            return True
        zone = await session.get(NetworkZone, asset.zone_id)
        if zone is None:
            return True
        days = zone.change_windows.get("change_window_days")
        start = zone.change_windows.get("change_window_start")
        end = zone.change_windows.get("change_window_end")
        if not days or not start or not end:
            return True
        now = self.now_provider()
        current_day = now.weekday()
        current_time = now.strftime("%H:%M")
        if current_day not in days or not (start <= current_time <= end):
            raise ChangeWindowBlockedError(zone.name, start, end)
        return True
