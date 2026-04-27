from pathlib import Path


def test_audit_migration_revokes_update_and_delete():
    migration = Path("migrations/versions/20260402_000001_initial.py").read_text()
    assert "REVOKE UPDATE, DELETE ON TABLE audit_log FROM PUBLIC" in migration


def test_audit_immutability_trigger_exists():
    migration = Path("migrations/versions/20260405_000007_audit_immutability_and_compliance.py").read_text()
    assert "prevent_audit_log_mutation" in migration
    assert "BEFORE UPDATE OR DELETE ON audit_log" in migration
