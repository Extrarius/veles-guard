# Illustrative examples for notes/part-5-control-observability/14-human-in-the-loop.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Protocol


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class ToolAction:
    id: str
    run_id: str
    tool: str
    args: Dict[str, Any]
    risk: RiskLevel
    reason: str
    created_at: datetime = field(default_factory=datetime.utcnow)


class Decision(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"


@dataclass
class ApprovalDecision:
    action_id: str
    decision: Decision
    approver_id: str
    reason: str
    decided_at: datetime = field(default_factory=datetime.utcnow)


class ApprovalService(Protocol):
    def request_approval(self, action: ToolAction) -> ApprovalDecision: ...


class AuditLogger(Protocol):
    def log_approval_requested(self, action: ToolAction) -> None: ...

    def log_approval_decision(self, decision: ApprovalDecision) -> None: ...

    def log_tool_executed(self, action: ToolAction, result: Any) -> None: ...


class Tool(Protocol):
    def call(self, args: Dict[str, Any]) -> Any: ...


@dataclass
class Runtime:
    tools: Dict[str, Tool]
    approval: ApprovalService
    audit: AuditLogger

    def execute(self, action: ToolAction) -> Any:
        tool = self.tools.get(action.tool)
        if tool is None:
            raise ValueError(f"unknown tool: {action.tool}")

        if requires_approval(action):
            self.audit.log_approval_requested(action)
            decision = self.approval.request_approval(action)
            self.audit.log_approval_decision(decision)

            if decision.decision != Decision.APPROVED:
                raise RuntimeError("tool action was not approved")

        result = tool.call(action.args)
        self.audit.log_tool_executed(action, result)
        return result


def requires_approval(action: ToolAction) -> bool:
    return action.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def classify_action(tool: str, args: Dict[str, Any]) -> tuple[RiskLevel, str]:
    if tool in ("send_email", "publish_post", "delete_file", "run_shell"):
        return RiskLevel.HIGH, "external side effect or destructive action"
    if tool in ("search_docs", "read_public_page"):
        return RiskLevel.LOW, "read-only action"
    if tool == "query_database":
        if args.get("readonly") is True:
            return RiskLevel.MEDIUM, "internal data access"
        return RiskLevel.HIGH, "database write operation"
    return RiskLevel.HIGH, "unknown tool requires explicit approval"
