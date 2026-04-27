import json
from collections.abc import Iterable


ACTIVE_SCAN_TOOLS = [
    "nmap",
    "snyk",
    "nessus",
    "qualys",
    "checkmarx",
    "sonarqube",
    "rapid7",
    "veracode",
    "burp_suite",
]

UPLOAD_TOOL_EXTENSIONS = {
    ".nessus": "nessus",
    ".xml": "nmap",
    ".json": "generic",
    ".csv": "generic",
}


def canonical_tool_name(source_tool: str) -> str:
    value = source_tool.strip().lower()
    aliases = {"burp": "burp_suite", "burpsuite": "burp_suite"}
    return aliases.get(value, value)


def infer_source_tool(filename: str, payload: str = "") -> str:
    lowered = filename.lower()
    for suffix, tool in UPLOAD_TOOL_EXTENSIONS.items():
        if lowered.endswith(suffix):
            inferred = tool
            break
    else:
        inferred = "generic"

    haystack = f"{lowered}\n{payload[:2000].lower()}"
    markers = {
        "sonarqube": "sonarqube",
        "checkmarx": "checkmarx",
        "veracode": "veracode",
        "rapid7": "rapid7",
        "qualys": "qualys",
        "nessus": "nessus",
        "snyk": "snyk",
        "burp": "burp_suite",
        "nmap": "nmap",
    }
    for marker, tool in markers.items():
        if marker in haystack:
            return tool
    return inferred


def normalize_tool_records(source_tool: str, records: list[dict]) -> list[dict]:
    tool = canonical_tool_name(source_tool)
    normalized = []
    for item in records:
        copy = dict(item)
        copy.setdefault("source_tool", tool)
        normalized.append(copy)
    return normalized


def parse_external_assets(payload: object) -> list[dict]:
    if payload is None:
        return []
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            return []
    if isinstance(payload, dict):
        for key in ("assets", "results", "items", "hosts", "resources"):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break
        else:
            payload = [payload]
    if not isinstance(payload, list):
        return []

    assets = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        hostname = item.get("hostname") or item.get("domain") or item.get("name")
        public_ip = item.get("public_ip") or item.get("ip") or item.get("ip_address")
        if not hostname and not public_ip:
            continue
        assets.append(
            {
                "hostname": hostname or public_ip,
                "public_ip": public_ip,
                "source": item.get("source") or item.get("provider") or "external_enumerator",
                "provider": item.get("provider"),
                "account": item.get("account"),
                "raw": item,
            }
        )
    return assets


def detect_shadow_assets(cloud_resources: Iterable[dict], known_assets: Iterable[object]) -> list[dict]:
    known_ips = {getattr(asset, "ip_address", None) for asset in known_assets if getattr(asset, "ip_address", None)}
    known_hostnames = {str(getattr(asset, "hostname", "")).lower() for asset in known_assets if getattr(asset, "hostname", None)}

    shadow = []
    for resource in cloud_resources:
        hostname = str(resource.get("hostname") or resource.get("name") or "").lower()
        public_ip = resource.get("public_ip") or resource.get("ip") or resource.get("ip_address")
        if public_ip in known_ips or (hostname and hostname in known_hostnames):
            continue
        shadow.append(
            {
                "hostname": resource.get("hostname") or resource.get("name") or public_ip or "unknown",
                "public_ip": public_ip,
                "provider": resource.get("provider", "unknown"),
                "account": resource.get("account"),
            }
        )
    return shadow
