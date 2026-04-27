import logging
import json
import re
from typing import Any

import httpx
from app.config import get_settings

logger = logging.getLogger(__name__)

STATIC_FALLBACK_TEMPLATES = {
    "patch": {
        "fix_steps": ["Identify the affected package version", "Apply vendor patch via package manager", "Restart affected service", "Confirm patch version"],
        "rollback_steps": ["Restore previous package version from backup", "Restart affected service", "Verify system stability"],
        "risk_narrative": "Unpatched software exposes the asset to known exploitation.",
        "business_impact": "Potential data breach or service disruption.",
        "compliance_impact": "May violate patch management controls across applicable frameworks.",
        "estimated_effort_hours": 2,
        "requires_downtime": True,
    },
    "configuration": {
        "fix_steps": ["Review current configuration against security baseline", "Apply recommended configuration change", "Validate change did not break dependent services"],
        "rollback_steps": ["Restore previous configuration from backup", "Validate service functionality"],
        "risk_narrative": "Misconfiguration creates an exploitable attack surface.",
        "business_impact": "Unauthorized access risk.",
        "compliance_impact": "Configuration management controls may be out of scope.",
        "estimated_effort_hours": 2,
        "requires_downtime": False,
    },
    "code": {
        "fix_steps": ["Identify vulnerable code path", "Apply secure coding fix", "Run unit and integration tests", "Deploy via CI/CD pipeline"],
        "rollback_steps": ["Revert commit", "Redeploy previous build", "Validate rollback"],
        "risk_narrative": "Vulnerable code can be exploited remotely.",
        "business_impact": "Application compromise risk.",
        "compliance_impact": "Secure development lifecycle controls affected.",
        "estimated_effort_hours": 8,
        "requires_downtime": False,
    },
    "manual": {
        "fix_steps": ["Review finding details with security team", "Assess manual remediation options", "Implement fix with change management approval", "Document remediation steps taken"],
        "rollback_steps": ["Reverse manual changes", "Document rollback actions"],
        "risk_narrative": "Manual intervention required — no automated fix available.",
        "business_impact": "Depends on asset criticality and exploit likelihood.",
        "compliance_impact": "Review applicable controls manually.",
        "estimated_effort_hours": 4,
        "requires_downtime": False,
    },
}


class LLMError(RuntimeError):
    pass


providers = ["OpenAIProvider"]  # expand later if needed


class LLMRouter:
    PROVIDER_ORDER = ("openai",)

    def __init__(self):
        self.settings = get_settings()

    def detect_fix_type(self, *, cve_description: str, cvss_vector: str | None, asset_type: str | None) -> str:
        description = cve_description.lower()
        if "patch" in description or (cvss_vector and "AV:N" in cvss_vector):
            return "patch"
        if asset_type == "web_app":
            return "code"
        if "config" in description:
            return "configuration"
        return "manual"

    def _fallback(self, fix_type: str) -> dict:
        payload = STATIC_FALLBACK_TEMPLATES[fix_type].copy()
        payload["fix_type"] = fix_type
        payload["plan_source"] = "fallback"
        return payload

    def _extract_json_payload(self, content: str) -> dict[str, Any]:
        content = content.strip()
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", content, re.DOTALL)
        if fenced:
            return json.loads(fenced.group(1))

        start = content.find("{")
        end = content.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(content[start : end + 1])

        raise LLMError("Model response did not contain valid JSON.")

    def _chat_completion_endpoints(self) -> list[str]:
        base_url = self.settings.openai_base_url.rstrip("/")
        endpoints: list[str] = []
        if base_url.endswith("/v1"):
            endpoints.append(f"{base_url}/chat/completions")
        else:
            endpoints.append(f"{base_url}/v1/chat/completions")
            endpoints.append(f"{base_url}/chat/completions")
        # Preserve order but remove duplicates.
        seen: set[str] = set()
        return [endpoint for endpoint in endpoints if not (endpoint in seen or seen.add(endpoint))]

    def _extract_chat_content(self, payload: dict[str, Any]) -> str:
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise LLMError("Model response did not include choices.")
        first_choice = choices[0]
        if not isinstance(first_choice, dict):
            raise LLMError("Model choice payload had unexpected shape.")
        message = first_choice.get("message")
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, str):
                text = content.strip()
                if text:
                    return text
            if isinstance(content, list):
                text = "".join(
                    part.get("text", "")
                    for part in content
                    if isinstance(part, dict)
                ).strip()
                if text:
                    return text
        provider_specific = first_choice.get("provider_specific_fields")
        if isinstance(provider_specific, dict):
            for key in ("content", "text", "output_text", "response"):
                value = provider_specific.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        finish_reason = first_choice.get("finish_reason")
        usage = payload.get("usage")
        if finish_reason == "length":
            raise LLMError(
                f"Model exhausted its completion budget before returning readable text. usage={usage}"
            )
        raise LLMError("Model response did not contain readable text.")

    async def _call_openai(self, prompt: dict[str, Any]) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.settings.openai_api_key}", "Content-Type": "application/json"}
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity remediation expert. "
                    "Return remediation guidance as valid JSON with keys: "
                    "fix_steps (list), rollback_steps (list), risk_narrative (str), "
                    "business_impact (str), compliance_impact (str), "
                    "estimated_effort_hours (int), requires_downtime (bool), "
                    "and optional fix_type (str). No markdown, no explanation."
                ),
            },
            {"role": "user", "content": json.dumps(prompt)},
        ]
        base_body = {
            "model": self.settings.openai_model,
            "messages": messages,
            "stream": False,
            "max_tokens": 4096,
            "temperature": 0.2,
            "reasoning_effort": "low",
        }
        async with httpx.AsyncClient(timeout=30.0, verify=True) as client:
            last_error: Exception | None = None
            for endpoint in self._chat_completion_endpoints():
                for request_body in (
                    base_body | {"response_format": {"type": "json_object"}},
                    base_body,
                ):
                    try:
                        response = await client.post(
                            endpoint,
                            headers=headers,
                            json=request_body,
                        )
                        response.raise_for_status()
                        payload = response.json()
                        content = self._extract_chat_content(payload)
                        return self._extract_json_payload(content)
                    except Exception as exc:
                        last_error = exc
                        continue
        raise LLMError(f"All OpenAI-compatible chat completion endpoints failed: {last_error}")

    async def generate_remediation_plan(self, finding: Any, asset: Any, controls: list[str], business_context: dict[str, Any]) -> dict[str, Any]:
        fix_type = self.detect_fix_type(
            cve_description=getattr(finding, "description", "") or getattr(finding, "cve_id", ""),
            cvss_vector=getattr(finding, "cvss_vector", None),
            asset_type=getattr(asset, "asset_type", None) or business_context.get("asset_type"),
        )
        prompt = {
            "cve_id": finding.cve_id,
            "cvss_score": finding.cvss_score,
            "epss_probability": finding.epss_score,
            "asset_ip": asset.ip_address if asset else None,
            "asset_type": getattr(asset, "asset_type", None) or business_context.get("asset_type", "server"),
            "asset_criticality": asset.criticality_score if asset else 0,
            "affected_compliance_frameworks": controls,
            "business_context": {
                "industry": business_context.get("industry_sector"),
                "revenue_tier": business_context.get("annual_revenue"),
            },
        }
        try:
            response = await self._call_openai(prompt)
            response["fix_type"] = response.get("fix_type", fix_type)
            response["plan_source"] = "llm"
            return response
        except Exception as exc:
            logger.warning(
                "llm_provider_failed",
                extra={"action": "llm_fallback", "provider": "openai", "error": str(exc)},
            )
            return self._fallback(fix_type)
