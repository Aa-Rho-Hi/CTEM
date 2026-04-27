from types import SimpleNamespace
from uuid import uuid4

import asyncio

from app.services.compliance_scoring import framework_score_breakdown
from app.tasks.compliance_update import recalculate_scores_in_session


class FakeScalarResult:
    def __init__(self, rows):
        self.rows = list(rows)

    def scalars(self):
        return self

    def all(self):
        return list(self.rows)


class FakeRowsResult:
    def __init__(self, rows):
        self.rows = list(rows)

    def all(self):
        return list(self.rows)


class FakeScalarOneResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class ComplianceScoreSession:
    def __init__(self):
        self.framework = SimpleNamespace(id=uuid4(), name="NIST CSF 2.0")
        self.control_1 = SimpleNamespace(id=uuid4(), control_id="PR.PS-3", title="Patch management")
        self.control_2 = SimpleNamespace(id=uuid4(), control_id="DE.CM-8", title="Scan review")
        self.added = []
        self.flushed = False

    async def execute(self, statement):
        sql = str(statement)
        if "FROM compliance_frameworks" in sql:
            return FakeScalarResult([self.framework])
        if "FROM compliance_controls" in sql and "GROUP BY" not in sql:
            return FakeScalarResult([self.control_1, self.control_2])
        if "FROM vulnerability_controls" in sql and "JOIN vulnerabilities" not in sql:
            return FakeRowsResult([
                (self.control_1.id, 2),
                (self.control_2.id, 1),
            ])
        if "FROM vulnerability_controls JOIN vulnerabilities" in sql:
            return FakeRowsResult([
                (self.control_2.id, 1),
            ])
        if "FROM compliance_scores" in sql:
            return FakeScalarOneResult(None)
        raise AssertionError(f"Unexpected SQL in fake session: {sql}")

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        self.flushed = True


def test_framework_score_breakdown_scores_controls_not_mapping_rows():
    session = ComplianceScoreSession()

    breakdown = asyncio.run(framework_score_breakdown(session, session.framework.id))

    assert breakdown["total_controls"] == 2
    assert breakdown["passing_controls"] == 1
    assert breakdown["failing_controls"] == 1
    assert breakdown["score"] == 50


def test_recalculate_scores_persists_control_level_score_metadata():
    session = ComplianceScoreSession()

    results = asyncio.run(recalculate_scores_in_session(session, "tenant-1"))

    assert results == {"NIST CSF 2.0": 50}
    assert session.flushed is True
    created_score = session.added[0]
    assert created_score.score == 50
    assert created_score.metadata_json["total_controls"] == 2
    assert created_score.metadata_json["passing_controls"] == 1
    assert created_score.metadata_json["failing_controls"] == 1
