# Illustrative examples for notes/part-8-practice/24-end-to-end-secure-agent-go.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional, Protocol, runtime_checkable


# --- Базовые типы ---


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class TrustLevel(str, Enum):
    TRUSTED_RUNTIME = "trusted_runtime"
    UNTRUSTED_USER = "untrusted_user"
    UNTRUSTED_TOOL = "untrusted_tool"


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]


@dataclass
class Plan:
    final_answer: str = ""
    tool_call: Optional[ToolCall] = None
    reason: str = ""


@dataclass
class ContextBlock:
    source: str
    trust: TrustLevel
    text: str


@dataclass
class RunRequest:
    run_id: str
    user_id: str
    task: str


@dataclass
class RunResult:
    run_id: str
    final_answer: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)


# --- Интерфейсы runtime ---


@runtime_checkable
class InputGuard(Protocol):
    def check(self, task: str) -> None: ...


@runtime_checkable
class ContextBuilder(Protocol):
    def build(self, req: RunRequest) -> list[ContextBlock]: ...


@runtime_checkable
class Planner(Protocol):
    def plan(self, req: RunRequest, blocks: list[ContextBlock]) -> Plan: ...


@runtime_checkable
class Policy(Protocol):
    def allow(self, req: RunRequest, call: ToolCall) -> RiskLevel: ...


@runtime_checkable
class SchemaValidator(Protocol):
    def validate(self, call: ToolCall) -> None: ...


@runtime_checkable
class ApprovalGate(Protocol):
    def approve(self, req: RunRequest, call: ToolCall, risk: RiskLevel) -> None: ...


@runtime_checkable
class ToolExecutor(Protocol):
    def execute(self, call: ToolCall) -> str: ...


@runtime_checkable
class OutputValidator(Protocol):
    def validate(self, text: str) -> None: ...


@runtime_checkable
class AuditLogger(Protocol):
    def log(self, event: "AuditEvent") -> None: ...


# --- Audit event ---


@dataclass
class AuditEvent:
    time: datetime
    run_id: str
    event: str
    component: str
    user_id: str = ""
    tool: str = ""
    risk: RiskLevel = RiskLevel.LOW
    decision: str = ""
    reason: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)


# --- Run budget ---


@dataclass
class Budget:
    max_steps: int
    max_tool_calls: int
    max_denied: int
    steps: int = 0
    tool_calls: int = 0
    denied: int = 0

    def check(self) -> None:
        if self.steps > self.max_steps:
            raise RuntimeError("budget exceeded: max steps")
        if self.tool_calls > self.max_tool_calls:
            raise RuntimeError("budget exceeded: max tool calls")
        if self.denied > self.max_denied:
            raise RuntimeError("budget exceeded: max denied actions")


# --- Runtime агента ---


@dataclass
class Runtime:
    input_guard: InputGuard
    context_builder: ContextBuilder
    planner: Planner
    policy: Policy
    schema: SchemaValidator
    approval: ApprovalGate
    executor: ToolExecutor
    output: OutputValidator
    audit: AuditLogger
    budget_factory: Callable[[], Budget]

    def run(self, req: RunRequest) -> RunResult:
        if not req.run_id:
            raise ValueError("run_id is required")

        result = RunResult(run_id=req.run_id)
        budget = self.budget_factory()

        try:
            self.input_guard.check(req.task)
        except Exception as exc:
            self.audit.log(
                AuditEvent(
                    time=datetime.now(timezone.utc),
                    run_id=req.run_id,
                    user_id=req.user_id,
                    event="input_blocked",
                    component="input_guard",
                    decision="denied",
                    reason=str(exc),
                )
            )
            raise

        blocks = self.context_builder.build(req)

        while True:
            budget.steps += 1
            try:
                budget.check()
            except Exception as exc:
                result.blocked.append("budget_exceeded")
                raise exc

            plan = self.planner.plan(req, blocks)

            if plan.tool_call is None:
                try:
                    self.output.validate(plan.final_answer)
                except Exception as exc:
                    result.blocked.append("output_blocked")
                    raise exc

                result.final_answer = plan.final_answer
                return result

            call = plan.tool_call
            budget.tool_calls += 1

            try:
                risk = self.policy.allow(req, call)
            except Exception as exc:
                budget.denied += 1
                result.blocked.append(f"tool_denied:{call.name}")
                self.audit.log(
                    AuditEvent(
                        time=datetime.now(timezone.utc),
                        run_id=req.run_id,
                        user_id=req.user_id,
                        event="tool_denied",
                        component="policy",
                        tool=call.name,
                        decision="denied",
                        reason=str(exc),
                    )
                )
                raise

            try:
                self.schema.validate(call)
            except Exception as exc:
                budget.denied += 1
                result.blocked.append(f"schema_validation_failed:{call.name}")
                raise exc

            if requires_approval(risk):
                try:
                    self.approval.approve(req, call, risk)
                except Exception as exc:
                    budget.denied += 1
                    result.blocked.append(f"approval_rejected:{call.name}")
                    raise exc

            observation = self.executor.execute(call)
            result.tool_calls.append(call)

            blocks.append(
                ContextBlock(
                    source=f"tool:{call.name}",
                    trust=TrustLevel.UNTRUSTED_TOOL,
                    text=observation,
                )
            )


def requires_approval(risk: RiskLevel) -> bool:
    return risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)


# --- Input guardrails ---


@dataclass
class Guard:
    max_chars: int

    def check(self, task: str) -> None:
        if not task.strip():
            raise ValueError("empty task")

        if len(task) > self.max_chars:
            raise ValueError("input too large")

        lower = task.lower()
        suspicious = [
            "ignore previous instructions",
            "disregard system prompt",
            "reveal your system prompt",
            "send secrets",
            "exfiltrate",
        ]

        for marker in suspicious:
            if marker in lower:
                raise ValueError("possible prompt injection")


# --- Context isolation ---


class Memory(Protocol):
    def read_for_user(self, user_id: str) -> list[ContextBlock]: ...


@dataclass
class Builder:
    memory: Memory

    def build(self, req: RunRequest) -> list[ContextBlock]:
        memory_blocks = self.memory.read_for_user(req.user_id)
        blocks = [
            ContextBlock(
                source="user_task",
                trust=TrustLevel.UNTRUSTED_USER,
                text=req.task,
            )
        ]
        blocks.extend(memory_blocks)
        return blocks


# --- Policy ---


class UserRole(str, Enum):
    READER = "reader"
    WRITER = "writer"
    ADMIN = "admin"


@dataclass
class User:
    id: str
    role: UserRole
    tools: list[str]


class UserStore(Protocol):
    def get_user(self, user_id: str) -> User: ...


@dataclass
class PolicyEngine:
    users: UserStore

    def allow(self, req: RunRequest, call: ToolCall) -> RiskLevel:
        user = self.users.get_user(req.user_id)

        if not _contains(user.tools, call.name):
            raise PermissionError(f"tool not allowed for user: {call.name}")

        if call.name == "search_docs":
            return RiskLevel.LOW

        if call.name in ("send_email", "delete_file", "run_shell"):
            if user.role != UserRole.ADMIN:
                raise PermissionError("high-risk tool requires admin role")
            return RiskLevel.HIGH

        raise PermissionError("unknown tool")


# --- Schema validation ---


@dataclass
class ToolSchemaValidator:
    allowed_args: dict[str, list[str]]

    def validate(self, call: ToolCall) -> None:
        allowed = self.allowed_args.get(call.name)
        if allowed is None:
            raise ValueError(f"schema not found for tool: {call.name}")

        for key in call.args:
            if not _contains(allowed, key):
                raise ValueError(f'unexpected arg "{key}" for tool {call.name}')

        if call.name == "search_docs":
            query = call.args.get("query")
            if not isinstance(query, str) or not query:
                raise ValueError("search_docs.query is required")


# --- Safe tool registry ---


class Tool(ABC):
    @abstractmethod
    def call(self, args: dict[str, Any]) -> str:
        raise NotImplementedError


@dataclass
class Registry:
    tools: dict[str, Tool]

    def get(self, name: str) -> Tool:
        tool = self.tools.get(name)
        if tool is None:
            raise KeyError(f"tool not registered: {name}")
        return tool


@dataclass
class Executor:
    registry: Registry
    audit: AuditLogger

    def execute(self, call: ToolCall) -> str:
        tool = self.registry.get(call.name)
        return tool.call(call.args)


# --- Output validation ---


SECRET_PATTERNS = [
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"]?[^'\"\s]+"),
    re.compile(r"(?i)bearer\s+[a-z0-9._\-]+"),
]


@dataclass
class OutputValidatorImpl:
    def validate(self, text: str) -> None:
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                raise ValueError("output contains possible secret")


# --- Минимальная сборка runtime ---


def new_runtime(
    input_guard: InputGuard,
    context_builder: ContextBuilder,
    planner: Planner,
    policy: Policy,
    schema: SchemaValidator,
    approval: ApprovalGate,
    executor: ToolExecutor,
    output: OutputValidator,
    audit: AuditLogger,
) -> Runtime:
    return Runtime(
        input_guard=input_guard,
        context_builder=context_builder,
        planner=planner,
        policy=policy,
        schema=schema,
        approval=approval,
        executor=executor,
        output=output,
        audit=audit,
        budget_factory=lambda: Budget(max_steps=8, max_tool_calls=4, max_denied=2),
    )


def _contains(items: list[str], want: str) -> bool:
    return want in items
