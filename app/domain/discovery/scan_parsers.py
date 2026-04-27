import csv
import hashlib
import io
import ipaddress
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_PORT_SPEC_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")

_FINDINGS_WRAPPER_KEYS = (
    "findings",
    "vulnerabilities",
    "issues",
    "results",
    "alerts",
    "hosts",
    "items",
    "data",
    "records",
    "entries",
    "scans",
    "ReportItems",
    "NessusClientData_v2",
)


def extract_cves_from_text(text: str) -> list[str]:
    return list(dict.fromkeys(match.upper() for match in _CVE_RE.findall(text)))


def _slugify_token(value: str) -> str:
    token = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return token or "finding"


def synthetic_finding_id(raw_record: dict, normalized) -> str:
    summary = (
        normalized.description
        or str(raw_record.get("vulnerability") or raw_record.get("title") or raw_record.get("name") or "generic finding")
    )
    asset_ref = normalized.asset_ip or str(raw_record.get("asset") or raw_record.get("hostname") or "unknown-asset")
    material = f"{normalized.source_tool}|{asset_ref}|{normalized.port or ''}|{summary}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12].upper()
    return f"GENERIC-{_slugify_token(summary)[:24].upper()}-{digest}"


def _stable_seed(value: str) -> int:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 100


def enrich_asset(asset_ip: str) -> dict[str, object]:
    seed = _stable_seed(asset_ip)
    criticality = 20 + (seed % 81)
    if criticality > 75:
        business_impact = "high"
    elif criticality > 40:
        business_impact = "medium"
    else:
        business_impact = "low"
    return {
        "asset_criticality": criticality,
        "is_crown_jewel": criticality > 90,
        "business_impact": business_impact,
        "internet_exposed": seed % 3 == 0,
        "attack_path_score": seed,
    }


def parse_observed_at(value: object) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def validate_scan_target(target: str) -> str:
    candidate = str(target).strip()
    if not candidate:
        raise ValueError("Scan target cannot be empty.")
    try:
        if "/" in candidate:
            ipaddress.ip_network(candidate, strict=False)
        else:
            ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ValueError(f"Invalid scan target: {candidate}") from exc
    return candidate


def validate_port_spec(ports: str) -> str:
    candidate = ports.strip()
    if not candidate:
        raise ValueError("Port specification cannot be empty.")
    if not _PORT_SPEC_RE.fullmatch(candidate):
        raise ValueError(f"Invalid port specification: {candidate}")
    for chunk in candidate.split(","):
        if "-" in chunk:
            start_raw, end_raw = chunk.split("-", 1)
            start = int(start_raw)
            end = int(end_raw)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {chunk}")
        else:
            port = int(chunk)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {port}")
    return candidate


def validate_nmap_extra_args(extra_args: object) -> None:
    if extra_args in (None, "", []):
        return
    raise ValueError("Custom nmap args are not supported.")


def flatten_json(obj, depth: int = 0) -> list[dict]:
    if depth > 4:
        return []
    if isinstance(obj, list) and obj and isinstance(obj[0], dict):
        return obj
    if isinstance(obj, dict):
        for key in _FINDINGS_WRAPPER_KEYS:
            value = obj.get(key)
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value
        for value in obj.values():
            result = flatten_json(value, depth + 1)
            if result:
                return result
        return [obj]
    return []


def parse_generic_xml(payload: str) -> list[dict]:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError:
        return []

    records: list[dict] = []
    children = list(root)
    if not children:
        return []

    candidates = children if len(children) > 1 else list(children[0])
    for elem in candidates:
        record: dict = {}
        for child in elem.iter():
            tag = child.tag.lower().split("}")[-1]
            text = (child.text or "").strip()
            if text:
                record[tag] = text
        if not record:
            continue
        elem_text = ET.tostring(elem, encoding="unicode")
        cves = extract_cves_from_text(elem_text)
        if cves:
            for cve in cves:
                records.append({**record, "cve_id": cve})
        else:
            records.append(record)
    return records


def parse_csv(payload: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(payload))
    try:
        rows = list(reader)
    except Exception:
        return []
    if not rows:
        return []
    normalized = []
    for row in rows:
        normalized.append({key.lower().strip().replace(" ", "_"): value for key, value in row.items() if value})
    return normalized


def parse_nmap_xml(payload: str) -> list[dict]:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ValueError("Invalid Nmap XML payload.") from exc

    findings: list[dict] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in {None, "up"}:
            continue

        asset_ip = None
        for address in host.findall("address"):
            if address.get("addrtype") in {"ipv4", "ipv6"}:
                asset_ip = address.get("addr")
                break
        if not asset_ip:
            continue

        hostnames = [node.get("name") for node in host.findall("hostnames/hostname") if node.get("name")]
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_number = int(port.get("portid", "0")) if port.get("portid") else None
            service = port.find("service")
            service_parts = [
                part
                for part in [
                    service.get("name") if service is not None else None,
                    service.get("product") if service is not None else None,
                    service.get("version") if service is not None else None,
                ]
                if part
            ]
            hostname_text = f" Hostnames: {', '.join(hostnames)}." if hostnames else ""
            base_description = (
                f"Open port detected on {asset_ip}:{port_number or 'unknown'}."
                f" Service: {' '.join(service_parts) if service_parts else 'unknown'}."
                f"{hostname_text}"
            ).strip()

            scripts = port.findall("script")
            cves: set[str] = set()
            for script in scripts:
                output = script.get("output", "")
                cves.update(match.upper() for match in _CVE_RE.findall(output))
            if cves:
                for cve in sorted(cves):
                    findings.append(
                        {
                            "cve_id": cve,
                            "asset_ip": asset_ip,
                            "port": port_number,
                            "severity": "high",
                            "description": base_description,
                        }
                    )
            else:
                findings.append(
                    {
                        "cve_id": None,
                        "asset_ip": asset_ip,
                        "port": port_number,
                        "severity": "info",
                        "description": base_description,
                    }
                )

    if not findings:
        raise ValueError("No hosts or open ports were found in the Nmap XML payload.")
    return findings

