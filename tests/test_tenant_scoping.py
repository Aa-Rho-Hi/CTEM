from uuid import uuid4

from sqlalchemy import select

from app.models.base import _add_tenant_criteria
from app.models.entities import Asset


def test_tenant_filter_hook_attaches_loader_criteria():
    tenant_id = uuid4()

    class DummySession:
        info = {"tenant_id": tenant_id}

    class DummyExecuteState:
        session = DummySession()
        is_select = True
        statement = select(Asset)

    state = DummyExecuteState()
    _add_tenant_criteria(state)
    compiled = str(state.statement)
    assert "assets" in compiled

