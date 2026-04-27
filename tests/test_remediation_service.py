from app.services.remediation_service import RemediationService


def test_normalize_fix_type_maps_verbose_patch_labels():
    assert RemediationService._normalize_fix_type("Security Patch and Compensating Controls") == "patch"


def test_normalize_fix_type_maps_hardening_labels():
    assert RemediationService._normalize_fix_type("Configuration Hardening") == "configuration"


def test_normalize_fix_type_defaults_to_manual():
    assert RemediationService._normalize_fix_type("Analyst Triage Workflow") == "manual"
