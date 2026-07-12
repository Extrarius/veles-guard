# Illustrative examples for notes/part-1-architecture-threats/01-introduction.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]


@dataclass
class Step:
    final_answer: str = ""
    tool_call: ToolCall | None = None


class LLMClient(Protocol):
    def plan(self, task: str) -> Step: ...

    def summarize(self, task: str, observation: str) -> str: ...


class Tool(Protocol):
    def call(self, args: dict[str, Any]) -> str: ...


class Policy(Protocol):
    def allow_tool_call(self, call: ToolCall) -> None: ...


class AuditLogger(Protocol):
    def tool_call_requested(self, call: ToolCall) -> None: ...

    def tool_call_denied(self, call: ToolCall, reason: Exception) -> None: ...

    def tool_call_executed(self, call: ToolCall, observation: str) -> None: ...


class Agent:
    def __init__(
        self,
        llm: LLMClient,
        tools: dict[str, Tool],
        policy: Policy,
        log: AuditLogger,
    ) -> None:
        self.llm = llm
        self.tools = tools
        self.policy = policy
        self.log = log

    def run(self, task: str) -> str:
        # Риск: prompt injection может быть уже внутри task.
        # Поэтому task нельзя считать доверенной управляющей инструкцией.
        step = self.llm.plan(task)

        if step.tool_call is None:
            # Риск: output может содержать секреты или галлюцинации.
            # В реальной системе здесь нужен output validation / redaction.
            return step.final_answer

        call = step.tool_call

        tool = self.tools.get(call.name)
        if tool is None:
            raise ValueError(f"unknown tool: {call.name}")

        # Риск: tool hijacking / tool misuse.
        # Модель не должна вызывать инструмент напрямую.
        # Сначала проверяем права, scope, параметры и необходимость approval.
        self.log.tool_call_requested(call)
        try:
            self.policy.allow_tool_call(call)
        except Exception as exc:
            self.log.tool_call_denied(call, exc)
            raise PermissionError(f"tool call denied: {exc}") from exc

        observation = tool.call(call.args)

        if not observation:
            raise ValueError("empty tool observation")

        self.log.tool_call_executed(call, observation)

        # Риск: tool output может быть poisoned.
        # Нельзя слепо превращать observation в новые инструкции.
        return self.llm.summarize(task, observation)
