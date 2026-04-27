import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.routes.remediation import remediation_history


class FakeScalarResult:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return self.rows


class FakeSession:
    def __init__(self, remediations, findings):
        self.remediations = remediations
        self.findings = findings

    async def execute(self, statement):
        filtered = self.remediations
        for criterion in statement._where_criteria:
            text = str(criterion)
            if "remediations.status" in text:
                value = criterion.right.value
                filtered = [item for item in filtered if item.status == value]
            if "remediations.created_at >=" in text:
                value = criterion.right.value
                filtered = [item for item in filtered if item.created_at >= value]
            if "remediations.created_at <=" in text:
                value = criterion.right.value
                filtered = [item for item in filtered if item.created_at <= value]

        offset = statement._offset_clause.value if statement._offset_clause is not None else 0
        limit = statement._limit_clause.value if statement._limit_clause is not None else len(filtered)
        return FakeScalarResult(filtered[offset : offset + limit])

    async def get(self, model, key):
        return self.findings.get(str(key))


def test_history_applies_pagination_and_date_range_filters():
    finding_a = SimpleNamespace(id=uuid4(), asset_id=uuid4(), sla_tier="Critical")
    finding_b = SimpleNamespace(id=uuid4(), asset_id=uuid4(), sla_tier="Low")
    remediations = [
        SimpleNamespace(id=uuid4(), vulnerability_id=finding_a.id, status="approved", created_at=datetime(2026, 4, 2, 10, tzinfo=timezone.utc)),
        SimpleNamespace(id=uuid4(), vulnerability_id=finding_b.id, status="approved", created_at=datetime(2026, 3, 28, 10, tzinfo=timezone.utc)),
    ]
    session = FakeSession(remediations, {str(finding_a.id): finding_a, str(finding_b.id): finding_b})

    result = asyncio.run(
        remediation_history(
            status="approved",
            date_from="2026-04-01",
            date_to="2026-04-02",
            limit=10,
            offset=0,
            session=session,
            current_user=SimpleNamespace(),
        )
    )

    assert result["limit"] == 10
    assert result["offset"] == 0
    assert len(result["items"]) == 1
    assert result["items"][0]["sla_tier"] == "Critical"


def test_history_filters_by_asset_and_offset():
    target_asset = uuid4()
    finding_a = SimpleNamespace(id=uuid4(), asset_id=target_asset, sla_tier="High")
    finding_b = SimpleNamespace(id=uuid4(), asset_id=uuid4(), sla_tier="High")
    remediations = [
        SimpleNamespace(id=uuid4(), vulnerability_id=finding_a.id, status="approved", created_at=datetime(2026, 4, 2, 10, tzinfo=timezone.utc)),
        SimpleNamespace(id=uuid4(), vulnerability_id=finding_b.id, status="approved", created_at=datetime(2026, 4, 1, 10, tzinfo=timezone.utc)),
    ]
    session = FakeSession(remediations, {str(finding_a.id): finding_a, str(finding_b.id): finding_b})

    result = asyncio.run(
        remediation_history(
            status="approved",
            asset_id=str(target_asset),
            limit=1,
            offset=0,
            session=session,
            current_user=SimpleNamespace(),
        )
    )

    assert len(result["items"]) == 1
    assert result["items"][0]["asset_id"] == str(target_asset)
