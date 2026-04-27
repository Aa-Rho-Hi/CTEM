import logging

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


class SplunkService:
    def __init__(self):
        self.settings = get_settings()

    async def send_event(self, sourcetype: str, event: dict) -> None:
        """Fire-and-forget POST to Splunk HEC. Never raises — Splunk must not break the main path."""
        url = self.settings.splunk_url
        token = self.settings.splunk_token
        if not url or not token or "mock" in url.lower() or "placeholder" in token.lower():
            return
        hec_url = url.rstrip("/") + "/services/collector/event"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    hec_url,
                    headers={"Authorization": f"Splunk {token}"},
                    json={"sourcetype": sourcetype, "event": event},
                )
        except Exception as exc:
            logger.debug("splunk.send_event failed (non-critical): %s", exc)
