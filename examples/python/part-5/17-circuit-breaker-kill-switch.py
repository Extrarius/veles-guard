# Illustrative examples for notes/part-5-control-observability/17-circuit-breaker-kill-switch.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Protocol


class State(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(self, threshold: int, cooldown_seconds: float) -> None:
        self._state = State.CLOSED
        self._failures = 0
        self._threshold = threshold
        self._opened_at = 0.0
        self._cooldown = cooldown_seconds
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            if self._state == State.CLOSED:
                return True
            if self._state == State.OPEN:
                if time.time() - self._opened_at >= self._cooldown:
                    self._state = State.HALF_OPEN
                    return True
                return False
            if self._state == State.HALF_OPEN:
                return True
            return False

    def success(self) -> None:
        with self._lock:
            self._failures = 0
            self._state = State.CLOSED

    def failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self._threshold:
                self._state = State.OPEN
                self._opened_at = time.time()


class KillSwitch(Protocol):
    def enabled(self, scope: str) -> bool: ...
    def activate(self, scope: str) -> None: ...


class MemoryKillSwitch:
    def __init__(self) -> None:
        self._closed: Dict[str, bool] = {}
        self._lock = threading.RLock()

    def activate(self, scope: str) -> None:
        with self._lock:
            self._closed[scope] = True

    def deactivate(self, scope: str) -> None:
        with self._lock:
            self._closed[scope] = False

    def enabled(self, scope: str) -> bool:
        with self._lock:
            return self._closed.get(scope, False)


def trip_agent_kill_switch(
    kill: KillSwitch, agent_id: str, revoke_credentials: bool = True
) -> None:
    """Disable agent (+ tools) and signal credential revocation."""
    kill.activate(f"agent:{agent_id}")
    kill.activate("tool:*")
    if revoke_credentials:
        # revoke/rotate tokens for agent_id in identity provider / secret store
        _ = agent_id


class Tool(Protocol):
    def call(self, args: Dict[str, Any]) -> Any: ...


class ErrToolDisabled(Exception):
    pass


class ErrCircuitOpen(Exception):
    pass


@dataclass
class SafeToolExecutor:
    tool_name: str
    tool: Tool
    breaker: CircuitBreaker
    kill: KillSwitch

    def call(self, args: Dict[str, Any]) -> Any:
        try:
            disabled = self.kill.enabled(f"tool:{self.tool_name}")
        except Exception as exc:
            # fail closed: если состояние kill-switch не удалось прочитать,
            # опаснее разрешить действие, чем заблокировать.
            raise exc

        if disabled:
            raise ErrToolDisabled("tool disabled by kill-switch")

        if not self.breaker.allow():
            raise ErrCircuitOpen("tool circuit breaker is open")

        try:
            result = self.tool.call(args)
        except Exception:
            self.breaker.failure()
            raise

        self.breaker.success()
        return result


@dataclass
class RunBudget:
    max_steps: int
    max_tool_calls: int
    max_denied: int
    steps: int = 0
    tool_calls: int = 0
    denied: int = 0

    def check(self) -> None:
        if self.steps > self.max_steps:
            raise RuntimeError(f"max steps exceeded: {self.steps}")
        if self.tool_calls > self.max_tool_calls:
            raise RuntimeError(f"max tool calls exceeded: {self.tool_calls}")
        if self.denied > self.max_denied:
            raise RuntimeError(f"max denied actions exceeded: {self.denied}")


def agent_loop(budget: RunBudget, next_fn: Callable[[], None]) -> None:
    while True:
        budget.steps += 1
        budget.check()
        next_fn()
