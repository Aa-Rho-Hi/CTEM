from types import SimpleNamespace

from app.services.compliance_mapper import ComplianceMapper, SUPPORTED_FRAMEWORKS


def test_compliance_mapper_supports_all_frameworks():
    assert len(SUPPORTED_FRAMEWORKS) == 10


def test_compliance_mapper_applies_zone_scoping():
    mapper = ComplianceMapper()
    pci_and_hipaa = mapper.map_cwe("CWE-311", pci=True, hipaa=True)
    no_zone_flags = mapper.map_cwe("CWE-311", pci=False, hipaa=False)
    assert ("PCI-DSS 4.0", "3.5") in pci_and_hipaa
    assert ("HIPAA", "164.312(e)") in pci_and_hipaa
    assert ("PCI-DSS 4.0", "3.5") not in no_zone_flags
    assert ("HIPAA", "164.312(e)") not in no_zone_flags


def test_compliance_mapper_derives_dynamic_controls_from_live_risk_signals():
    mapper = ComplianceMapper()
    vulnerability = SimpleNamespace(
        cwe_id=None,
        severity="Critical",
        cvss_score=9.8,
        is_kev=True,
        source_tool="nmap",
        port=443,
        validation_status="verified",
    )
    zone = SimpleNamespace(pci=True, hipaa=True)
    asset = SimpleNamespace(criticality_score=95)

    controls = mapper.derive_mappings(vulnerability, zone, asset)

    assert ("NIST CSF 2.0", "PR.PS-3") in controls
    assert ("NIST CSF 2.0", "DE.CM-8") in controls
    assert ("NIST CSF 2.0", "RS.MI-3") in controls
    assert ("PCI-DSS 4.0", "6.3.3") in controls
    assert ("HIPAA", "164.308(a)(1)") in controls


def test_compliance_mapper_prefers_secure_config_controls_for_missing_security_headers():
    mapper = ComplianceMapper()
    vulnerability = SimpleNamespace(
        cwe_id=None,
        severity="Low",
        cvss_score=0,
        is_kev=False,
        source_tool="generic",
        port=None,
        validation_status="",
    )

    controls = mapper.derive_mappings(vulnerability, None, None, finding_text="Missing Security Headers")

    assert ("NIST CSF 2.0", "PR.DS") in controls
    assert ("NIST CSF 2.0", "PR.IP") in controls
    assert ("NIST CSF 2.0", "PR.DS-2") not in controls


def test_compliance_mapper_maps_weak_password_policy_to_access_controls():
    mapper = ComplianceMapper()
    vulnerability = SimpleNamespace(
        cwe_id=None,
        severity="Medium",
        cvss_score=0,
        is_kev=False,
        source_tool="generic",
        port=None,
        validation_status="",
    )

    controls = mapper.derive_mappings(vulnerability, None, None, finding_text="Weak Password Policy")

    assert ("NIST CSF 2.0", "PR.AC") in controls
    assert ("NIST CSF 2.0", "PR.PS-3") not in controls


def test_compliance_mapper_prefers_secure_coding_for_sql_injection():
    mapper = ComplianceMapper()
    vulnerability = SimpleNamespace(
        cwe_id="CWE-89",
        severity="High",
        cvss_score=8.1,
        is_kev=False,
        source_tool="generic",
        port=443,
        validation_status="",
    )

    controls = mapper.derive_mappings(vulnerability, None, None, finding_text="SQL Injection Risk")

    assert ("NIST CSF 2.0", "PR.DS") in controls
    assert ("NIST CSF 2.0", "DE.CM") in controls
    assert ("ISO 27001:2022", "A.8.28") in controls
    assert ("ISO 27001:2022", "A.8.8") not in controls


def test_compliance_mapper_keeps_patch_and_vulnerability_controls_for_rce():
    mapper = ComplianceMapper()
    vulnerability = SimpleNamespace(
        cwe_id=None,
        severity="Critical",
        cvss_score=9.8,
        is_kev=False,
        source_tool="generic",
        port=443,
        validation_status="",
    )

    controls = mapper.derive_mappings(vulnerability, None, None, finding_text="Remote Code Execution")

    assert ("NIST CSF 2.0", "PR.PS-3") in controls
    assert ("ISO 27001:2022", "A.8.8") in controls
