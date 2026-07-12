# Illustrative examples for notes/part-6-multi-agent-security/18-inter-agent-security.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Protocol


AgentID = str


class Scope(str, Enum):
    READ_DOCS = "read:docs"
    WEB_SEARCH = "web:search"
    SEND_EMAIL = "send:email"
    DB_WRITE = "db:write"
    SHELL_RUN = "shell:run"


@dataclass
class AgentIdentity:
    id: AgentID
    role: str
    allowed_tools: List[str] = field(default_factory=list)
    allowed_scopes: List[Scope] = field(default_factory=list)
    handoff_targets: List[AgentID] = field(default_factory=list)
    prompt_version: str = ""
    policy_version: str = ""


def has_scope(scopes: List[Scope], want: Scope) -> bool:
    return want in scopes


class TrustLevel(str, Enum):
    TRUSTED_RUNTIME = "trusted_runtime"
    UNTRUSTED_INPUT = "untrusted_input"
    AGENT_OUTPUT = "agent_output"


@dataclass
class AgentMessage:
    id: str
    run_id: str
    parent_action_id: str
    from_agent: AgentID
    to_agent: AgentID
    task: str
    data_refs: List[str] = field(default_factory=list)
    delegated_scopes: List[Scope] = field(default_factory=list)
    trust: TrustLevel = TrustLevel.TRUSTED_RUNTIME
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class HandoffPolicy:
    agents: Dict[AgentID, AgentIdentity]

    def allow_handoff(self, msg: AgentMessage) -> None:
        from_agent = self.agents.get(msg.from_agent)
        if from_agent is None:
            raise ValueError(f"unknown source agent: {msg.from_agent}")

        to_agent = self.agents.get(msg.to_agent)
        if to_agent is None:
            raise ValueError(f"unknown target agent: {msg.to_agent}")

        if not _contains_agent(from_agent.handoff_targets, msg.to_agent):
            raise ValueError(f"handoff from {msg.from_agent} to {msg.to_agent} is not allowed")

        for scope in msg.delegated_scopes:
            if not has_scope(from_agent.allowed_scopes, scope):
                raise ValueError(f"source agent does not own scope: {scope.value}")
            if not has_scope(to_agent.allowed_scopes, scope):
                raise ValueError(f"target agent cannot receive scope: {scope.value}")

        if msg.trust == TrustLevel.UNTRUSTED_INPUT:
            raise ValueError("untrusted input cannot be delegated without sanitization")


def _contains_agent(items: List[AgentID], want: AgentID) -> bool:
    return want in items


@dataclass
class HandoffBudget:
    max_depth: int
    max_handoffs: int
    max_agents: int
    depth: int = 0
    handoffs: int = 0
    agents_involved: Dict[AgentID, bool] = field(default_factory=dict)

    def check(self, next_agent: AgentID) -> None:
        self.handoffs += 1
        self.agents_involved[next_agent] = True

        if self.depth > self.max_depth:
            raise RuntimeError("max handoff depth exceeded")
        if self.handoffs > self.max_handoffs:
            raise RuntimeError("max handoffs exceeded")
        if len(self.agents_involved) > self.max_agents:
            raise RuntimeError("max agents involved exceeded")


class Agent(Protocol):
    def run(self, msg: AgentMessage) -> AgentMessage: ...


class AuditLogger(Protocol):
    def log_handoff(self, msg: AgentMessage, decision: str, reason: str) -> None: ...


@dataclass
class HandoffExecutor:
    policy: HandoffPolicy
    agents: Dict[AgentID, Agent]
    audit: AuditLogger
    budget: HandoffBudget

    def execute(self, msg: AgentMessage) -> AgentMessage:
        try:
            self.budget.check(msg.to_agent)
        except Exception as exc:
            self.audit.log_handoff(msg, "denied", str(exc))
            raise

        try:
            self.policy.allow_handoff(msg)
        except Exception as exc:
            self.audit.log_handoff(msg, "denied", str(exc))
            raise

        agent = self.agents.get(msg.to_agent)
        if agent is None:
            reason = f"agent not registered: {msg.to_agent}"
            self.audit.log_handoff(msg, "denied", reason)
            raise ValueError(reason)

        self.audit.log_handoff(msg, "allowed", "handoff policy passed")
        return agent.run(msg)
