import hashlib
import re
from datetime import datetime, timedelta, timezone

import httpx
import msgpack
try:
    from redis.asyncio import Redis
except ImportError:  # pragma: no cover
    Redis = object

from app.config import get_settings

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

_CURATED_CVE_OVERRIDES = {
    "CVE-2021-44228": {
        "cvss_base_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss_probability": 0.0,
        "is_kev": True,
        "cwe_id": "CWE-917",
    },
    "CVE-2020-1472": {
        "cvss_base_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_probability": 0.0,
        "is_kev": True,
        "cwe_id": "NVD-CWE-noinfo",
    },
    "CVE-2019-0708": {
        "cvss_base_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_probability": 0.0,
        "is_kev": True,
        "cwe_id": "CWE-416",
    },
    "CVE-2022-30190": {
        "cvss_base_score": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "epss_probability": 0.0,
        "is_kev": True,
        "cwe_id": "NVD-CWE-noinfo",
    },
}


class NvdClient:
    HTTP_TIMEOUT_SECONDS = 0.5

    def __init__(self, redis: Redis):
        self.redis = redis
        self.settings = get_settings()

    @staticmethod
    def _stable_seed(value: str) -> int:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return int(digest[:8], 16) % 100

    @staticmethod
    def _normalize_cve_id(cve_id: str) -> str:
        return str(cve_id or "").strip().upper()

    @staticmethod
    def _is_refreshable_cached_payload(payload: dict | None) -> bool:
        return not payload or payload.get("source") == "mock"

    def mock_response(self, cve_id: str) -> dict:
        seed = self._stable_seed(cve_id)
        cvss_base_score = float(4 + (seed % 7))  # 4.0 - 10.0 inclusive
        epss_probability = round(seed / 100.0, 2)
        is_kev = seed > 80
        return {
            "cve_id": cve_id,
            "cvss_base_score": cvss_base_score,
            "cvss_vector": None,
            "epss_probability": epss_probability,
            "is_kev": is_kev,
            "cwe_id": None,
            "cached_until": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
            "source": "mock",
        }

    def curated_response(self, cve_id: str) -> dict | None:
        override = _CURATED_CVE_OVERRIDES.get(cve_id)
        if override is None:
            return None
        return {
            "cve_id": cve_id,
            **override,
            "cached_until": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
            "source": "curated",
        }

    @staticmethod
    def _pick_primary_metric(metrics: dict) -> dict:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key) or []
            if not metric_list:
                continue
            preferred = next((item for item in metric_list if item.get("type") == "Primary"), None)
            if preferred is None:
                preferred = next(
                    (
                        item
                        for item in metric_list
                        if str(item.get("source", "")).lower().endswith("nist.gov")
                    ),
                    None,
                )
            if preferred is None:
                preferred = metric_list[0]
            cvss_data = preferred.get("cvssData", {})
            if cvss_data:
                return cvss_data
        return {}

    @staticmethod
    def _pick_cwe_value(weaknesses: list[dict]) -> str | None:
        if not weaknesses:
            return None
        preferred_weaknesses = [
            weakness
            for weakness in weaknesses
            if str(weakness.get("source", "")).lower().endswith("nist.gov")
        ]
        search_groups = [preferred_weaknesses, weaknesses] if preferred_weaknesses else [weaknesses]
        for group in search_groups:
            for weakness in group:
                descriptions = weakness.get("description", [])
                preferred = next(
                    (
                        item.get("value")
                        for item in descriptions
                        if item.get("value") and item.get("lang") == "en" and item.get("value") != "NVD-CWE-noinfo"
                    ),
                    None,
                )
                if preferred:
                    return preferred
        for group in search_groups:
            for weakness in group:
                descriptions = weakness.get("description", [])
                fallback = next((item.get("value") for item in descriptions if item.get("value")), None)
                if fallback:
                    return fallback
        return None

    def _parse_payload(self, cve_id: str, payload: dict) -> dict:
        vuln = payload.get("vulnerabilities", [{}])[0].get("cve", {})
        metrics = vuln.get("metrics", {})
        primary_metric = self._pick_primary_metric(metrics)
        weaknesses = vuln.get("weaknesses", [])
        cwe_value = self._pick_cwe_value(weaknesses)
        return {
            "cve_id": cve_id,
            "cvss_base_score": float(primary_metric.get("baseScore", 0) or 0),
            "cvss_vector": primary_metric.get("vectorString"),
            "epss_probability": float(payload.get("epss_probability") or payload.get("epss") or 0),
            "is_kev": bool(
                payload.get("is_kev")
                or payload.get("kev")
                or vuln.get("cisaExploitAdd")
                or vuln.get("cisaActionDue")
                or vuln.get("cisaRequiredAction")
            ),
            "cwe_id": cwe_value,
            "cached_until": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
            "source": "nvd",
        }

    async def _read_cache(self, cache_key: str) -> dict | None:
        try:
            cached = await self.redis.get(cache_key)
            if cached:
                return msgpack.unpackb(cached, raw=False)
        except Exception:
            return None
        return None

    async def _write_cache(self, cache_key: str, payload: dict) -> None:
        try:
            await self.redis.set(cache_key, msgpack.packb(payload, use_bin_type=True), ex=86400)
        except Exception:
            pass

    async def _fetch_nvd_payload(self, cve_id: str) -> dict:
        timeout = httpx.Timeout(self.HTTP_TIMEOUT_SECONDS)
        async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
            response = await client.get(
                self.settings.nist_nvd_base_url,
                params={"cveId": cve_id},
                headers={"apiKey": self.settings.nvd_api_key},
            )
            response.raise_for_status()
            return response.json()

    async def bulk_fetch(self, cve_ids: list[str]) -> dict[str, dict]:
        """Fetch NVD data for multiple CVEs using a single Redis mget instead of N individual gets."""
        if not cve_ids:
            return {}
        unique_ids = list(dict.fromkeys(cve_ids))
        cache_keys = [f"nvd:{cve_id}" for cve_id in unique_ids]
        try:
            cached_values = await self.redis.mget(*cache_keys)
        except Exception:
            cached_values = [None] * len(unique_ids)
        result: dict[str, dict] = {}
        miss_ids: list[str] = []
        for cve_id, cached in zip(unique_ids, cached_values):
            if cached:
                try:
                    result[cve_id] = msgpack.unpackb(cached, raw=False)
                    continue
                except Exception:
                    pass
            miss_ids.append(cve_id)
        for cve_id in miss_ids:
            result[cve_id] = await self.fetch(cve_id)
        return result

    async def fetch(self, cve_id: str) -> dict:
        cve_id = self._normalize_cve_id(cve_id)
        cache_key = f"nvd:{cve_id}"
        cached_payload = await self._read_cache(cache_key)
        if cached_payload and not self._is_refreshable_cached_payload(cached_payload):
            return cached_payload

        remote_error = None
        if _CVE_ID_RE.fullmatch(cve_id):
            try:
                payload = await self._fetch_nvd_payload(cve_id)
                parsed = self._parse_payload(cve_id, payload)
                await self._write_cache(cache_key, parsed)
                return parsed
            except Exception as exc:
                remote_error = exc

        curated = self.curated_response(cve_id)
        if curated is not None:
            await self._write_cache(cache_key, curated)
            return curated

        if cached_payload is not None:
            return cached_payload

        if self.settings.environment == "development":
            parsed = self.mock_response(cve_id)
            await self._write_cache(cache_key, parsed)
            return parsed

        if remote_error is not None:
            raise remote_error
        raise RuntimeError(f"Unable to fetch NVD enrichment for {cve_id}")
