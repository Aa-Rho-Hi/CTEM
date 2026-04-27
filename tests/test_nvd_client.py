import asyncio

import msgpack

from app.services.nvd_client import NvdClient


class FakeRedis:
    def __init__(self):
        self.store = {}

    async def get(self, key):
        return self.store.get(key)

    async def mget(self, *keys):
        return [self.store.get(key) for key in keys]

    async def set(self, key, value, ex=None):
        self.store[key] = value


class BrokenRedis:
    async def get(self, key):
        raise ConnectionError("redis down")

    async def set(self, key, value, ex=None):
        raise ConnectionError("redis down")


async def _raise_timeout(*args, **kwargs):
    raise TimeoutError("nvd timed out")


async def _sample_nvd_payload(*args, **kwargs):
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "baseScore": 10.0,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                },
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-917"},
                                {"lang": "en", "value": "CWE-20"},
                            ]
                        }
                    ],
                    "cisaExploitAdd": "2021-12-10",
                }
            }
        ]
    }


def test_nvd_client_uses_curated_override_for_known_cve_when_remote_unavailable(monkeypatch):
    redis = FakeRedis()
    client = NvdClient(redis)
    client.settings.environment = "development"
    monkeypatch.setattr(client, "_fetch_nvd_payload", _raise_timeout)

    payload = asyncio.run(client.fetch("CVE-2021-44228"))
    assert payload["cve_id"] == "CVE-2021-44228"
    assert payload["cvss_base_score"] == 10.0
    assert payload["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert payload["is_kev"] is True
    assert payload["cwe_id"] == "CWE-917"
    assert payload["source"] == "curated"
    assert "nvd:CVE-2021-44228" in redis.store


def test_nvd_client_dev_mode_tolerates_redis_failure():
    client = NvdClient(BrokenRedis())
    client.settings.environment = "development"
    client._fetch_nvd_payload = _raise_timeout

    payload = asyncio.run(client.fetch("CVE-2026-0002"))

    assert payload["cve_id"] == "CVE-2026-0002"
    assert payload["source"] == "mock"


def test_nvd_client_refreshes_stale_mock_cache_before_returning_known_cve(monkeypatch):
    redis = FakeRedis()
    client = NvdClient(redis)
    client.settings.environment = "development"
    stale_mock = client.mock_response("CVE-2021-44228")
    redis.store["nvd:CVE-2021-44228"] = msgpack.packb(stale_mock, use_bin_type=True)
    monkeypatch.setattr(client, "_fetch_nvd_payload", _raise_timeout)

    payload = asyncio.run(client.fetch("CVE-2021-44228"))

    assert payload["source"] == "curated"
    assert payload["cvss_base_score"] == 10.0
    cached = msgpack.unpackb(redis.store["nvd:CVE-2021-44228"], raw=False)
    assert cached["source"] == "curated"
    assert cached["cwe_id"] == "CWE-917"


def test_nvd_client_dev_mode_falls_back_to_mock_for_unknown_cve(monkeypatch):
    client = NvdClient(FakeRedis())
    client.settings.environment = "development"
    monkeypatch.setattr(client, "_fetch_nvd_payload", _raise_timeout)

    first = asyncio.run(client.fetch("CVE-2026-1111"))
    second = asyncio.run(client.fetch("CVE-2026-1111"))

    assert first["source"] == "mock"
    assert second["source"] == "mock"
    assert first["cvss_base_score"] == second["cvss_base_score"]
    assert first["epss_probability"] == second["epss_probability"]
    assert first["is_kev"] == second["is_kev"]
    assert first["cwe_id"] is None
    assert first["cvss_vector"] is None


def test_nvd_client_prefers_real_nvd_payload_when_available(monkeypatch):
    client = NvdClient(FakeRedis())
    client.settings.environment = "development"
    monkeypatch.setattr(client, "_fetch_nvd_payload", _sample_nvd_payload)

    payload = asyncio.run(client.fetch("CVE-2021-44228"))

    assert payload["source"] == "nvd"
    assert payload["cvss_base_score"] == 10.0
    assert payload["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert payload["is_kev"] is True
    assert payload["cwe_id"] == "CWE-917"


def test_nvd_client_prefers_nist_cwe_over_vendor_cwe():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "metrics": {},
                    "weaknesses": [
                        {
                            "source": "security@apache.org",
                            "description": [{"lang": "en", "value": "CWE-20"}],
                        },
                        {
                            "source": "nvd@nist.gov",
                            "description": [{"lang": "en", "value": "CWE-917"}],
                        },
                    ],
                }
            }
        ]
    }

    parsed = NvdClient(FakeRedis())._parse_payload("CVE-2021-44228", payload)

    assert parsed["cwe_id"] == "CWE-917"
