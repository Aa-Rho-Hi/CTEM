import time
from typing import Any

import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.config import Settings, get_settings
from app.core.security import require_roles
from app.services.llm_router import LLMRouter

router = APIRouter(prefix="/llm-config", tags=["llm-config"])


class LLMTestRequest(BaseModel):
    prompt: str = "Return the word PONG and nothing else."


def _chat_completion_endpoints(settings: Settings) -> list[str]:
    base_url = settings.openai_base_url.rstrip("/")
    endpoints: list[str] = []
    if base_url.endswith("/v1"):
        endpoints.append(f"{base_url}/chat/completions")
    else:
        endpoints.append(f"{base_url}/v1/chat/completions")
        endpoints.append(f"{base_url}/chat/completions")
    seen: set[str] = set()
    return [endpoint for endpoint in endpoints if not (endpoint in seen or seen.add(endpoint))]


def _extract_content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        first_choice = choices[0]
        if isinstance(first_choice, dict):
            message = first_choice.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str) and content.strip():
                    return content.strip()
                if isinstance(content, list):
                    text = "".join(
                        part.get("text", "")
                        for part in content
                        if isinstance(part, dict)
                    ).strip()
                    if text:
                        return text
            text = first_choice.get("text")
            if isinstance(text, str) and text.strip():
                return text.strip()

    output_text = payload.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    output = payload.get("output")
    if isinstance(output, list):
        chunks: list[str] = []
        for item in output:
            if not isinstance(item, dict):
                continue
            for part in item.get("content", []):
                if isinstance(part, dict):
                    text = part.get("text")
                    if isinstance(text, str) and text.strip():
                        chunks.append(text.strip())
        if chunks:
            return "\n".join(chunks)

    raise ValueError("Provider returned no readable text content.")


def _payload_debug_preview(payload: dict[str, Any]) -> dict[str, Any]:
    preview: dict[str, Any] = {"keys": sorted(payload.keys())[:20]}
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            preview["choice_keys"] = sorted(first.keys())
            message = first.get("message")
            if isinstance(message, dict):
                preview["message_keys"] = sorted(message.keys())
                content = message.get("content")
                preview["message_content_type"] = type(content).__name__
                if isinstance(content, list):
                    preview["message_content_preview"] = content[:2]
                elif isinstance(content, str):
                    preview["message_content_preview"] = content[:200]
            if "text" in first:
                preview["text_preview"] = str(first.get("text"))[:200]
    output = payload.get("output")
    if isinstance(output, list) and output:
        preview["output_preview"] = output[:1]
    if "output_text" in payload:
        preview["output_text_preview"] = str(payload.get("output_text"))[:200]
    return preview


@router.get("", dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def get_llm_config():
    settings = get_settings()
    return {
        "active_provider": "openai",
        "model": settings.openai_model,
        "fallback_status": "enabled",
        "fallback_target": "static_templates",
        "environment": settings.environment,
        "base_url": settings.openai_base_url,
        "endpoint_candidates": _chat_completion_endpoints(settings),
    }


@router.post("/test", dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def test_llm_config(payload: LLMTestRequest):
    settings = get_settings()
    headers = {"Authorization": f"Bearer {settings.openai_api_key}", "Content-Type": "application/json"}
    router = LLMRouter()
    body = {
        "model": settings.openai_model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity assistant. "
                    "Return a concise plain-text answer to the user's prompt. "
                    "Do not leave the response empty."
                ),
            },
            {"role": "user", "content": payload.prompt},
        ],
        "stream": False,
        "temperature": 0.2,
        "max_tokens": 2000,
    }
    start = time.monotonic()
    last_error: str | None = None

    async with httpx.AsyncClient(timeout=60.0, verify=True) as client:
        for endpoint in _chat_completion_endpoints(settings):
            try:
                response = await client.post(endpoint, headers=headers, json=body)
                response.raise_for_status()
                payload_json = response.json()
                content = _extract_content(payload_json)
                latency_ms = int((time.monotonic() - start) * 1000)
                return {
                    "status": "ok",
                    "response": content,
                    "latency_ms": latency_ms,
                    "endpoint": endpoint,
                    "fallback_active": False,
                }
            except Exception as exc:
                last_error = str(exc)

    latency_ms = int((time.monotonic() - start) * 1000)
    return {
        "status": "error",
        "response": "",
        "latency_ms": latency_ms,
        "fallback_active": True,
        "error": last_error,
    }
