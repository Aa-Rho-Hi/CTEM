import asyncio
from types import SimpleNamespace

from app.services.llm_router import LLMRouter, STATIC_FALLBACK_TEMPLATES


def _finding():
    return SimpleNamespace(cve_id="CVE-2026-0001", cvss_score=7.5, epss_score=0.42, cvss_vector="CVSS:3.1/AV:N", description="patch required")


def _asset():
    return SimpleNamespace(ip_address="10.0.0.10", criticality_score=50, asset_type="server")


def test_openai_success(monkeypatch):
    router = LLMRouter()
    router.settings.environment = "production"

    async def fake_call_openai(prompt):
        return {
            "fix_type": "patch",
            "fix_steps": ["a"],
            "rollback_steps": ["b"],
            "risk_narrative": "r",
            "business_impact": "b",
            "compliance_impact": "c",
            "estimated_effort_hours": 2,
            "requires_downtime": True,
        }

    router._call_openai = fake_call_openai
    payload = asyncio.run(router.generate_remediation_plan(_finding(), _asset(), ["NIST"], {"industry_sector": "finance", "annual_revenue": "mid"}))
    assert payload["fix_type"] == "patch"
    assert payload["fix_steps"]


def test_openai_failure_uses_fallback():
    router = LLMRouter()
    router.settings.environment = "production"

    async def fake_call_openai(prompt):
        raise RuntimeError("boom")

    router._call_openai = fake_call_openai
    payload = asyncio.run(router.generate_remediation_plan(_finding(), _asset(), ["NIST"], {"industry_sector": "finance", "annual_revenue": "mid"}))
    assert payload["fix_type"] == "patch"
    assert payload["risk_narrative"] == STATIC_FALLBACK_TEMPLATES["patch"]["risk_narrative"]


def test_fallback_all_four_types():
    router = LLMRouter()
    for fix_type in ("patch", "configuration", "code", "manual"):
        payload = router._fallback(fix_type)
        assert payload["fix_type"] == fix_type
        assert payload["fix_steps"]


def test_extract_json_payload_from_fenced_block():
    router = LLMRouter()
    payload = router._extract_json_payload("""```json
{"fix_steps":["a"],"rollback_steps":["b"],"risk_narrative":"r","business_impact":"b","compliance_impact":"c","estimated_effort_hours":1,"requires_downtime":false}
```""")
    assert payload["fix_steps"] == ["a"]


def test_chat_completion_endpoints_prefers_v1_for_compatible_gateway():
    router = LLMRouter()
    router.settings.openai_base_url = "https://chat-api.tamu.ai/openai"
    assert router._chat_completion_endpoints() == [
        "https://chat-api.tamu.ai/openai/v1/chat/completions",
        "https://chat-api.tamu.ai/openai/chat/completions",
    ]


def test_extract_chat_content_reads_provider_specific_text():
    router = LLMRouter()
    payload = {
        "choices": [
            {
                "message": {"content": ""},
                "provider_specific_fields": {"text": '{"fix_steps":["a"],"rollback_steps":["b"],"risk_narrative":"r","business_impact":"b","compliance_impact":"c","estimated_effort_hours":1,"requires_downtime":false}'},
            }
        ]
    }
    assert router._extract_chat_content(payload).startswith("{")
