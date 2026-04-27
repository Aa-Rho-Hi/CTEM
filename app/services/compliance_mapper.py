import re
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

SUPPORTED_FRAMEWORKS = [
    "NIST CSF 2.0",
    "PCI-DSS 4.0",
    "SOC 2 Type II",
    "HIPAA",
    "CMMC Level 2",
    "ISO 27001:2022",
    "GDPR",
    "CCPA",
    "NYDFS 23 NYCRR 500",
    "CRI Profile 2.0",
]


CONTROL_MAPPINGS = {
    "CWE-79": [("NIST CSF 2.0", "PR.DS-2"), ("PCI-DSS 4.0", "6.3")],
    "CWE-89": [("NIST CSF 2.0", "PR.DS"), ("PCI-DSS 4.0", "6.3"), ("SOC 2 Type II", "CC6.1"), ("ISO 27001:2022", "A.8.28")],
    "CWE-287": [("NIST CSF 2.0", "PR.AC-1"), ("HIPAA", "164.312(d)"), ("CMMC Level 2", "AC.1.001")],
    "CWE-311": [("PCI-DSS 4.0", "3.5"), ("HIPAA", "164.312(e)"), ("GDPR", "Art.32")],
    "CWE-400": [("NIST CSF 2.0", "PR.DS-4"), ("SOC 2 Type II", "A1.1")],
    "CWE-22": [("ISO 27001:2022", "A.8.12"), ("SOC 2 Type II", "CC7.1")],
    "CWE-352": [("NIST CSF 2.0", "PR.AC-4"), ("PCI-DSS 4.0", "6.4")],
    "CWE-434": [("NIST CSF 2.0", "PR.PS-5"), ("CMMC Level 2", "CM.2.061")],
    "CWE-601": [("SOC 2 Type II", "CC6.7"), ("GDPR", "Art.25")],
    "CWE-918": [("NIST CSF 2.0", "PR.IR-1"), ("ISO 27001:2022", "A.5.15")],
    "CWE-798": [("NYDFS 23 NYCRR 500", "500.12"), ("CMMC Level 2", "IA.2.078")],
    "CWE-732": [("NIST CSF 2.0", "PR.AC-6"), ("CRI Profile 2.0", "IAM-01")],
    "CWE-319": [("GDPR", "Art.32"), ("CCPA", "1798.150")],
    "CWE-16": [("ISO 27001:2022", "A.5.9"), ("NYDFS 23 NYCRR 500", "500.3")],
    "CWE-269": [("NIST CSF 2.0", "PR.AC-4"), ("HIPAA", "164.308(a)(4)")],
    "CWE-200": [("GDPR", "Art.5"), ("CCPA", "1798.100")],
    "CWE-125": [("SOC 2 Type II", "CC6.6"), ("ISO 27001:2022", "A.8.11")],
    "CWE-190": [("NIST CSF 2.0", "PR.DS-6"), ("CRI Profile 2.0", "THM-03")],
    "CWE-284": [("CMMC Level 2", "AC.1.001"), ("NYDFS 23 NYCRR 500", "500.7")],
    "CWE-862": [("HIPAA", "164.312(a)"), ("PCI-DSS 4.0", "7.2")],
}

CONTROL_TITLES = {
    ("NIST CSF 2.0", "PR.DS"): "Data security protections",
    ("NIST CSF 2.0", "PR.AC"): "Identity management and access control",
    ("NIST CSF 2.0", "PR.IP"): "Secure configuration and change management",
    ("NIST CSF 2.0", "DE.CM"): "Security monitoring for anomalous activity",
    ("NIST CSF 2.0", "PR.PS-3"): "Vulnerability and patch management",
    ("PCI-DSS 4.0", "6.3.3"): "Security vulnerabilities are identified and remediated",
    ("ISO 27001:2022", "A.8.8"): "Management of technical vulnerabilities",
    ("NIST CSF 2.0", "DE.CM-8"): "Vulnerability scans are performed and reviewed",
    ("SOC 2 Type II", "CC7.1"): "System vulnerabilities are identified and addressed",
    ("CRI Profile 2.0", "THM-03"): "External attack surface monitoring",
    ("NIST CSF 2.0", "PR.DS-10"): "Secure development and code review",
    ("ISO 27001:2022", "A.8.28"): "Secure coding practices",
    ("NIST CSF 2.0", "RS.MI-3"): "Newly identified vulnerabilities are mitigated",
    ("NYDFS 23 NYCRR 500", "500.16"): "Incident response and remediation governance",
    ("HIPAA", "164.308(a)(1)"): "Security incident procedures and risk management",
}

INFRA_SCAN_TOOLS = {"nmap", "nessus", "qualys", "rapid7", "openvas"}
APPSEC_TOOLS = {"snyk", "checkmarx", "sonarqube", "veracode", "burp"}
HIGH_RISK_PORTS = {21, 22, 80, 443, 445, 3389, 5432, 8080, 8443, 9200}

DESCRIPTION_RULES = [
    {
        "pattern": re.compile(r"missing security headers?|security headers?", re.I),
        "include": [
            ("NIST CSF 2.0", "PR.DS"),
            ("NIST CSF 2.0", "PR.IP"),
        ],
        "exclude": [
            ("NIST CSF 2.0", "PR.DS-2"),
        ],
    },
    {
        "pattern": re.compile(r"weak password policy|password policy|weak passwords?", re.I),
        "include": [
            ("NIST CSF 2.0", "PR.AC"),
            ("HIPAA", "164.312(d)"),
            ("CMMC Level 2", "AC.1.001"),
            ("NYDFS 23 NYCRR 500", "500.12"),
        ],
        "exclude": [
            ("NIST CSF 2.0", "PR.PS-3"),
        ],
    },
    {
        "pattern": re.compile(r"sql injection|sqli", re.I),
        "include": [
            ("NIST CSF 2.0", "PR.DS"),
            ("NIST CSF 2.0", "DE.CM"),
            ("ISO 27001:2022", "A.8.28"),
        ],
        "exclude": [
            ("NIST CSF 2.0", "PR.DS-1"),
            ("ISO 27001:2022", "A.8.8"),
        ],
    },
    {
        "pattern": re.compile(r"remote code execution|\brce\b", re.I),
        "include": [
            ("NIST CSF 2.0", "PR.PS-3"),
            ("ISO 27001:2022", "A.8.8"),
        ],
        "exclude": [],
    },
]


class ComplianceMapper:
    def map_cwe(self, cwe: str, *, pci: bool, hipaa: bool) -> list[tuple[str, str]]:
        mappings = []
        for framework, control in CONTROL_MAPPINGS.get(cwe, []):
            if framework == "PCI-DSS 4.0" and not pci:
                continue
            if framework == "HIPAA" and not hipaa:
                continue
            mappings.append((framework, control))
        return mappings

    def derive_mappings(self, vulnerability, asset_zone=None, asset=None, finding_text: str | None = None) -> list[tuple[str, str]]:
        pci = bool(asset_zone and getattr(asset_zone, "pci", False))
        hipaa = bool(asset_zone and getattr(asset_zone, "hipaa", False))
        controls: list[tuple[str, str]] = list(self.map_cwe(getattr(vulnerability, "cwe_id", "") or "", pci=pci, hipaa=hipaa))

        severity = str(getattr(vulnerability, "severity", "") or "").lower()
        source_tool = str(getattr(vulnerability, "source_tool", "") or "").lower()
        cvss_score = float(getattr(vulnerability, "cvss_score", 0) or 0)
        port = getattr(vulnerability, "port", None)
        is_kev = bool(getattr(vulnerability, "is_kev", False))
        validation_status = str(getattr(vulnerability, "validation_status", "") or "").lower()
        asset_criticality = int(getattr(asset, "criticality_score", 0) or 0) if asset is not None else 0

        if severity in {"critical", "high"} or cvss_score >= 7 or is_kev or asset_criticality >= 80:
            controls.extend(
                [
                    ("NIST CSF 2.0", "PR.PS-3"),
                    ("PCI-DSS 4.0", "6.3.3"),
                    ("ISO 27001:2022", "A.8.8"),
                ]
            )

        if source_tool in INFRA_SCAN_TOOLS or port in HIGH_RISK_PORTS:
            controls.extend(
                [
                    ("NIST CSF 2.0", "DE.CM-8"),
                    ("SOC 2 Type II", "CC7.1"),
                    ("CRI Profile 2.0", "THM-03"),
                ]
            )

        if source_tool in APPSEC_TOOLS:
            controls.extend(
                [
                    ("NIST CSF 2.0", "PR.DS-10"),
                    ("SOC 2 Type II", "CC6.1"),
                    ("ISO 27001:2022", "A.8.28"),
                ]
            )

        if validation_status in {"verified", "confirmed"} or is_kev:
            controls.extend(
                [
                    ("NIST CSF 2.0", "RS.MI-3"),
                    ("NYDFS 23 NYCRR 500", "500.16"),
                ]
            )
            if hipaa:
                controls.append(("HIPAA", "164.308(a)(1)"))

        finding_text = (finding_text or "").strip()
        if finding_text:
            for rule in DESCRIPTION_RULES:
                if rule["pattern"].search(finding_text):
                    excluded = set(rule["exclude"])
                    controls = [control for control in controls if control not in excluded]
                    controls.extend(rule["include"])

        unique_controls: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for framework, control in controls:
            if framework == "PCI-DSS 4.0" and not pci:
                continue
            if framework == "HIPAA" and not hipaa:
                continue
            key = (framework, control)
            if key in seen:
                continue
            seen.add(key)
            unique_controls.append(key)
        return unique_controls

    def control_title(self, framework: str, control_id: str) -> str:
        return CONTROL_TITLES.get((framework, control_id), f"{framework} {control_id}")

    def _iter_catalog_definitions(self) -> Iterable[tuple[str, str, str, str | None]]:
        for cwe, mappings in CONTROL_MAPPINGS.items():
            for framework, control_id in mappings:
                yield framework, control_id, self.control_title(framework, control_id), cwe
        seen: set[tuple[str, str]] = set()
        for framework, control_id in CONTROL_TITLES:
            key = (framework, control_id)
            if key in seen:
                continue
            seen.add(key)
            yield framework, control_id, self.control_title(framework, control_id), None

    async def ensure_frameworks_and_controls(self, session):
        from app.models.entities import ComplianceControl, ComplianceFramework

        framework_index = {
            framework.name: framework
            for framework in (await session.execute(select(ComplianceFramework))).scalars().all()
        }
        for framework_name in SUPPORTED_FRAMEWORKS:
            if framework_name not in framework_index:
                try:
                    framework = ComplianceFramework(name=framework_name, version="current")
                    session.add(framework)
                    await session.flush()
                    framework_index[framework_name] = framework
                except IntegrityError:
                    await session.rollback()
                    framework = (
                        await session.execute(select(ComplianceFramework).where(ComplianceFramework.name == framework_name))
                    ).scalar_one()
                    framework_index[framework_name] = framework

        existing_controls = {
            (control.framework_id, control.control_id): control
            for control in (await session.execute(select(ComplianceControl))).scalars().all()
        }
        for framework_name, control_id, title, cwe_tag in self._iter_catalog_definitions():
            framework = framework_index[framework_name]
            key = (framework.id, control_id)
            existing = existing_controls.get(key)
            if existing is not None:
                tags = list(existing.cwe_tags or [])
                if cwe_tag and cwe_tag not in tags:
                    existing.cwe_tags = [*tags, cwe_tag]
                if not getattr(existing, "title", None):
                    existing.title = title
                continue
            control = ComplianceControl(
                framework_id=framework.id,
                control_id=control_id,
                title=title,
                cwe_tags=[cwe_tag] if cwe_tag else [],
            )
            session.add(control)
            existing_controls[key] = control
        await session.flush()
        return framework_index

    async def ingest_vulnerability_controls(self, session, vulnerability, asset_zone, asset=None):
        from app.models.entities import ComplianceControl, ScanFinding, VulnerabilityControl

        framework_index = await self.ensure_frameworks_and_controls(session)
        finding_text = ""
        if getattr(vulnerability, "scan_finding_id", None):
            scan_finding = await session.get(ScanFinding, vulnerability.scan_finding_id)
            if scan_finding is not None:
                payload = scan_finding.normalized_payload or {}
                finding_text = str(
                    payload.get("description")
                    or payload.get("vulnerability")
                    or payload.get("title")
                    or ""
                )
        mappings = self.derive_mappings(vulnerability, asset_zone, asset, finding_text=finding_text)
        if not mappings:
            return []

        controls = (await session.execute(select(ComplianceControl))).scalars().all()
        selected_controls = []
        for framework_name, control_id in mappings:
            framework = framework_index[framework_name]
            control = next(
                (item for item in controls if item.control_id == control_id and item.framework_id == framework.id),
                None,
            )
            if control is not None:
                selected_controls.append(control)

        created = []
        existing_mappings = {
            control_id
            for control_id in (
                await session.execute(
                    select(VulnerabilityControl.control_id).where(VulnerabilityControl.vulnerability_id == vulnerability.id)
                )
            ).scalars().all()
        }
        for control in selected_controls:
            if control.id in existing_mappings:
                continue
            record = VulnerabilityControl(
                tenant_id=vulnerability.tenant_id,
                vulnerability_id=vulnerability.id,
                control_id=control.id,
            )
            session.add(record)
            created.append(record)
            existing_mappings.add(control.id)
        await session.flush()
        return created

    async def sync_vulnerability_controls(self, session):
        from app.models.entities import Asset, NetworkZone, Vulnerability

        assets = {
            asset.id: asset
            for asset in (await session.execute(select(Asset))).scalars().all()
        }
        zones = {
            zone.id: zone
            for zone in (await session.execute(select(NetworkZone))).scalars().all()
        }
        vulnerabilities = (await session.execute(select(Vulnerability))).scalars().all()

        created_count = 0
        for vulnerability in vulnerabilities:
            asset = assets.get(vulnerability.asset_id) if vulnerability.asset_id else None
            zone = zones.get(asset.zone_id) if asset and asset.zone_id else None
            created_count += len(await self.ingest_vulnerability_controls(session, vulnerability, zone, asset))
        await session.flush()
        return created_count
