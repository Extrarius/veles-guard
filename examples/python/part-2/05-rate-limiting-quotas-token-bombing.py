# Illustrative examples for notes/part-2-input-security/05-rate-limiting-quotas-token-bombing.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional, Protocol, Tuple


def estimate_tokens(text: str) -> int:
    # Очень грубое приближение для конспекта:
    # 1 token ≈ 4 chars для английского.
    # Для русского и смешанного текста оценка может отличаться.
    chars = len(text)
    if chars == 0:
        return 0
    return chars // 4 + 1


@dataclass
class RequestLimits:
    max_bytes: int
    max_input_tokens: int
    max_requests_min: int


@dataclass
class AdmissionDecision:
    allowed: bool
    reason: str = ""


def check_admission(input_text: str, limits: RequestLimits) -> AdmissionDecision:
    encoded = input_text.encode("utf-8")
    if len(encoded) > limits.max_bytes:
        return AdmissionDecision(
            allowed=False,
            reason=f"input too large: {len(encoded)} bytes",
        )

    estimated_tokens = estimate_tokens(input_text)
    if estimated_tokens > limits.max_input_tokens:
        return AdmissionDecision(
            allowed=False,
            reason=f"input token budget exceeded: {estimated_tokens} tokens",
        )

    return AdmissionDecision(allowed=True)


@dataclass
class Bucket:
    count: int = 0
    reset_time: float = 0.0


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float) -> None:
        self._limit = limit
        self._window = window_seconds
        self._buckets: dict[str, Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, subject: str) -> bool:
        with self._lock:
            now = time.time()
            bucket = self._buckets.get(subject, Bucket())

            if now > bucket.reset_time:
                bucket = Bucket(count=0, reset_time=now + self._window)

            if bucket.count >= self._limit:
                self._buckets[subject] = bucket
                return False

            bucket.count += 1
            self._buckets[subject] = bucket
            return True


@dataclass
class AgentBudget:
    max_steps: int
    max_tool_calls: int
    max_tokens: int
    steps: int = 0
    tool_calls: int = 0
    tokens: int = 0

    def add_step(self) -> None:
        self.steps += 1
        if self.steps > self.max_steps:
            raise ValueError(f"agent step budget exceeded: {self.steps}")

    def add_tool_call(self) -> None:
        self.tool_calls += 1
        if self.tool_calls > self.max_tool_calls:
            raise ValueError(f"tool call budget exceeded: {self.tool_calls}")

    def add_tokens(self, n: int) -> None:
        self.tokens += n
        if self.tokens > self.max_tokens:
            raise ValueError(f"token budget exceeded: {self.tokens}")


@dataclass
class AgentStep:
    observation: str
    uses_tool: bool


class StepRunner(Protocol):
    def next(self) -> Tuple[AgentStep, bool, Optional[BaseException]]: ...


def run_with_budget(runner: StepRunner, budget: AgentBudget) -> None:
    while True:
        budget.add_step()

        step, done, err = runner.next()
        if err is not None:
            raise err
        if done:
            return

        if step.uses_tool:
            budget.add_tool_call()

        budget.add_tokens(estimate_tokens(step.observation))
