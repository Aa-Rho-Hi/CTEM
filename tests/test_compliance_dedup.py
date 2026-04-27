import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.services.compliance_mapper import ComplianceMapper, SUPPORTED_FRAMEWORKS


class FakeScalarResult:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return self.rows


class FakeSession:
    def __init__(self, frameworks, controls=None, mappings=None):
        self.frameworks = frameworks
        self.controls = controls or []
        self.mappings = mappings or []
        self.added = []

    async def execute(self, statement):
        text = str(statement)
        if "compliance_frameworks" in text:
            return FakeScalarResult(self.frameworks)
        if "vulnerability_controls.control_id" in text:
            return FakeScalarResult(self.mappings)
        if "compliance_controls" in text:
            return FakeScalarResult(self.controls)
        return FakeScalarResult([])

    def add(self, obj):
        self.added.append(obj)
        if obj.__class__.__name__ == "ComplianceControl":
            self.controls.append(obj)

    async def flush(self):
        return None


def test_ensure_frameworks_and_controls_deduplicates_reused_control_ids():
    frameworks = [SimpleNamespace(id=uuid4(), name=name) for name in SUPPORTED_FRAMEWORKS]
    session = FakeSession(frameworks=frameworks)
    asyncio.run(ComplianceMapper().ensure_frameworks_and_controls(session))

    nist_controls = [control for control in session.added if getattr(control, "framework_id", None) == frameworks[0].id]
    pr_ac_4 = [control for control in nist_controls if control.control_id == "PR.AC-4"]

    assert len(pr_ac_4) == 1
    assert sorted(pr_ac_4[0].cwe_tags) == ["CWE-269", "CWE-352"]


def test_ingest_vulnerability_controls_skips_existing_rows():
    framework = SimpleNamespace(id=uuid4(), name="NIST CSF 2.0")
    control = SimpleNamespace(id=uuid4(), framework_id=framework.id, control_id="PR.DS-2", cwe_tags=["CWE-79"])
    vulnerability = SimpleNamespace(id=uuid4(), tenant_id=uuid4(), cwe_id="CWE-79")
    zone = SimpleNamespace(pci=False, hipaa=False)
    session = FakeSession(frameworks=[framework], controls=[control], mappings=[control.id])

    created = asyncio.run(ComplianceMapper().ingest_vulnerability_controls(session, vulnerability, zone))

    assert created == []
