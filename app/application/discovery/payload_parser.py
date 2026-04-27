import asyncio
import json

from app.config import get_settings
from app.domain.discovery.scan_parsers import flatten_json, parse_csv, parse_generic_xml, parse_nmap_xml


def llm_extract_findings(payload: str) -> list[dict]:
    import httpx

    settings = get_settings()
    api_key = settings.openai_api_key
    if not api_key or api_key in ("placeholder", ""):
        return []

    system_prompt = (
        "You are a security data parser. Extract all vulnerability/finding records from the "
        "provided scan output and return them as a JSON array. Each object must have these fields "
        "(use null if unknown): cve_id, asset_ip, port, severity (critical/high/medium/low/info), "
        "description. Return ONLY the JSON array, no explanation."
    )
    snippet = payload[:8000]

    async def _call():
        base_url = settings.openai_base_url.rstrip("/")
        endpoint = f"{base_url}/chat/completions" if base_url.endswith("/v1") else f"{base_url}/v1/chat/completions"
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                endpoint,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": settings.openai_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": snippet},
                    ],
                    "max_tokens": 2000,
                    "temperature": 0,
                    "stream": False,
                },
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"].strip()
            start = content.find("[")
            end = content.rfind("]")
            if start != -1 and end != -1:
                return json.loads(content[start : end + 1])
            return []

    try:
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(_call())
        loop.close()
        return result if isinstance(result, list) else []
    except Exception:
        return []


def coerce_payload_records(payload: str, source_tool: str) -> list[dict]:
    if not payload or not payload.strip():
        raise ValueError("Uploaded file is empty.")

    if source_tool == "nmap" or payload.lstrip().startswith("<?xml") and "nmaprun" in payload[:500]:
        try:
            return parse_nmap_xml(payload)
        except ValueError:
            pass

    stripped = payload.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
            records = flatten_json(parsed)
            if records:
                return records
        except json.JSONDecodeError:
            pass

    if stripped.startswith("<"):
        records = parse_generic_xml(stripped)
        if records:
            return records

    if "\n" in stripped and "," in stripped.split("\n")[0]:
        records = parse_csv(stripped)
        if records:
            return records

    records = llm_extract_findings(payload)
    if records:
        return records

    raise ValueError(
        "Could not parse scan file. Supported: Nmap XML, Nessus XML, JSON (array or object), CSV. "
        "Ensure the file contains vulnerability/finding data."
    )

