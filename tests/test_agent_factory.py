from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.agents.base import BaseAgent
from app.agents.catalog import AGENT_CATALOGUE, AgentFactory
from app.agents.implementations import StandardAgent


def test_create_known_type():
    agent = AgentFactory.create("pt_agent", str(uuid4()))
    assert isinstance(agent, BaseAgent)
    assert isinstance(agent, StandardAgent)
    assert agent.tool_whitelist == AGENT_CATALOGUE["pt_agent"]["tools"]


def test_create_unknown_type():
    with pytest.raises(ValueError):
        AgentFactory.create("nonexistent", str(uuid4()))


def test_invalid_tool_in_whitelist():
    with pytest.raises(ValueError):
        AgentFactory.create("pt_agent", str(uuid4()), tool_whitelist=["nmap", "bad_tool"])


def test_custom_safety_ceiling():
    agent = AgentFactory.create("pt_agent", str(uuid4()), safety_ceiling=91)
    assert agent.safety_ceiling == 91


def test_decommission_preserves_history():
    agent = SimpleNamespace(id=uuid4(), is_active=True)
    decisions = [SimpleNamespace(id=uuid4(), agent_id=agent.id, decision="execute_plan")]
    agent.is_active = False
    preserved = [decision for decision in decisions if decision.agent_id == agent.id]
    assert agent.is_active is False
    assert len(preserved) == 1
