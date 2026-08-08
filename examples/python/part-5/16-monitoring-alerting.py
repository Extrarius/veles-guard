# Illustrative examples for notes/part-5-control-observability/16-monitoring-alerting.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Protocol


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class SecuritySignal:
    run_id: str
    user_hash: str
    event: str
    tool: str
    severity: Severity
    reason: str
    time: Optional[datetime] = None
    attrs: Dict[str, str] = field(default_factory=dict)


class CounterStore:
    def __init__(self) -> None:
        self._counts: Dict[str, int] = {}
        self._lock = threading.Lock()

    def inc(self, key: str) -> None:
        with self._lock:
            self._counts[key] = self._counts.get(key, 0) + 1

    def get(self, key: str) -> int:
        with self._lock:
            return self._counts.get(key, 0)


@dataclass
class Alert:
    name: str
    severity: Severity
    message: str
    run_id: str


class AlertSink(Protocol):
    def send(self, alert: Alert) -> None: ...


@dataclass
class Rule:
    name: str
    event: str
    threshold: int
    severity: Severity

    def evaluate(
        self, signal: SecuritySignal, store: CounterStore
    ) -> Optional[Alert]:
        if signal.event != self.event:
            return None

        key = f"{self.event}:{signal.user_hash}:{signal.tool}"
        store.inc(key)

        if store.get(key) < self.threshold:
            return None

        return Alert(
            name=self.name,
            severity=self.severity,
            message=(
                f"threshold reached for event={signal.event} tool={signal.tool}"
            ),
            run_id=signal.run_id,
        )


@dataclass
class Monitor:
    store: CounterStore
    rules: List[Rule]
    sink: AlertSink

    def handle(self, signal: SecuritySignal) -> None:
        if signal.time is None:
            signal.time = datetime.now(timezone.utc)

        for rule in self.rules:
            alert = rule.evaluate(signal, self.store)
            if alert is None:
                continue
            self.sink.send(alert)


RULES: List[Rule] = [
    Rule(
        name="Prompt injection spike",
        event="prompt_injection_detected",
        threshold=5,
        severity=Severity.HIGH,
    ),
    Rule(
        name="Repeated denied tool calls",
        event="tool_denied",
        threshold=3,
        severity=Severity.MEDIUM,
    ),
    Rule(
        name="Blocked egress attempts",
        event="egress_blocked",
        threshold=1,
        severity=Severity.HIGH,
    ),
    Rule(
        name="Budget runaway",
        event="budget_exceeded",
        threshold=1,
        severity=Severity.HIGH,
    ),
]


@dataclass
class WeakSignals:
    """Weak signals for one run (scope drift / monitoring tampering)."""

    new_external_domain: bool = False
    credential_search: bool = False
    monitoring_tampering: bool = False
    out_of_scope_action: bool = False
    continue_after_deny: bool = False
    real_secret_access: bool = False


def should_auto_stop(s: WeakSignals) -> bool:
    """True on emergency-stop hard trigger. Stop via §17.

    Correlation (new domain + credential search + tampering + out-of-scope)
    is covered by these flags; credential_search alone does not stop.
    """
    return (
        s.monitoring_tampering
        or s.continue_after_deny
        or s.real_secret_access
        or s.new_external_domain
        or s.out_of_scope_action
    )


@dataclass
class TrajectorySignals:
    """Compositional flags for one run (≠ scope_drift)."""

    external_identity_created: bool = False
    unsolicited_human_contact: bool = False
    unrequested_repo_modify: bool = False
    goal_read_only_analysis: bool = False


def should_stop_trajectory(t: TrajectorySignals) -> bool:
    """True on compositional violation vs goal. Separate from should_auto_stop."""
    if t.external_identity_created and t.unsolicited_human_contact:
        return True
    if t.goal_read_only_analysis and t.unrequested_repo_modify:
        return True
    return False
