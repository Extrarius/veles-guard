# Illustrative examples for notes/part-3-processing-security/06-rbac-tool-permissions.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

from enum import Enum
from typing import Any, Protocol


class Risk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ToolAction(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    SEND = "send"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class Actor:
    def __init__(self, user_id: str, roles: list[str], scopes: list[str]) -> None:
        self.user_id = user_id
        self.roles = roles
        self.scopes = scopes


class ToolCall:
    def __init__(
        self,
        name: str,
        action: ToolAction,
        resource: str,
        args: dict[str, Any],
        risk: Risk,
    ) -> None:
        self.name = name
        self.action = action
        self.resource = resource
        self.args = args
        self.risk = risk


class Policy(Protocol):
    def decide(self, actor: Actor, call: ToolCall) -> Decision: ...


class SimplePolicy:
    def decide(self, actor: Actor, call: ToolCall) -> Decision:
        if call.action in (ToolAction.DELETE, ToolAction.EXECUTE):
            return Decision.REQUIRE_APPROVAL

        if call.risk == Risk.HIGH:
            return Decision.REQUIRE_APPROVAL

        required_scope = f"{call.name}:{call.action.value}"
        if not _has_scope(actor.scopes, required_scope):
            return Decision.DENY

        return Decision.ALLOW


def _has_scope(scopes: list[str], required: str) -> bool:
    return required in scopes


class Tool(Protocol):
    def call(self, args: dict[str, Any]) -> str: ...


class AuditLogger(Protocol):
    def log_decision(self, actor: Actor, call: ToolCall, decision: Decision) -> None: ...


class Runtime:
    def __init__(
        self,
        policy: Policy,
        tools: dict[str, Tool],
        audit: AuditLogger,
    ) -> None:
        self.policy = policy
        self.tools = tools
        self.audit = audit

    def execute_tool(self, actor: Actor, call: ToolCall) -> str:
        decision = self.policy.decide(actor, call)
        self.audit.log_decision(actor, call, decision)

        if decision == Decision.DENY:
            raise PermissionError("tool call denied")
        if decision == Decision.REQUIRE_APPROVAL:
            raise PermissionError("tool call requires human approval")
        if decision == Decision.ALLOW:
            tool = self.tools.get(call.name)
            if tool is None:
                raise ValueError(f"unknown tool: {call.name}")
            return tool.call(call.args)

        raise ValueError("unknown policy decision")
