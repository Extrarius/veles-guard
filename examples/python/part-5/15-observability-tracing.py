# Illustrative examples for notes/part-5-control-observability/15-observability-tracing.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


@dataclass
class AuditEvent:
    run_id: str
    event: str
    severity: Severity
    component: str
    time: Optional[datetime] = None
    correlation_id: str = ""
    agent_id: str = ""
    agent_owner: str = ""
    on_behalf_of: str = ""
    role: str = ""
    effective_scope: str = ""
    tool: str = ""
    operation: str = ""
    resource: str = ""
    approval_id: str = ""
    risk: str = ""
    decision: str = ""
    reason: str = ""
    attrs: Dict[str, Any] = field(default_factory=dict)


SECRET_PATTERNS = [
    re.compile(
        r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[^'\"\s]+"
    ),
    re.compile(r"(?i)bearer\s+[a-z0-9._\-]+"),
]


def redact(value: str) -> str:
    out = value
    for pattern in SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class Logger:
    def emit(self, event: AuditEvent) -> None:
        if event.time is None:
            event.time = datetime.now(timezone.utc)

        if event.attrs:
            for key, value in event.attrs.items():
                if isinstance(value, str):
                    event.attrs[key] = redact(value)

        payload = {
            "time": event.time.isoformat(),
            "run_id": event.run_id,
            "event": event.event,
            "severity": event.severity.value,
            "component": event.component,
            "tool": event.tool or None,
            "risk": event.risk or None,
            "decision": event.decision or None,
            "reason": event.reason or None,
            "attrs": event.attrs or None,
        }
        print(json.dumps({k: v for k, v in payload.items() if v is not None}))


def log_policy_decision(
    logger: Logger,
    run_id: str,
    tool: str,
    decision: str,
    reason: str,
    risk: str,
    args: Dict[str, Any],
) -> None:
    args_json = json.dumps(args)
    logger.emit(
        AuditEvent(
            run_id=run_id,
            event="policy_decision",
            severity=Severity.INFO,
            component="policy",
            tool=tool,
            risk=risk,
            decision=decision,
            reason=reason,
            attrs={"args_hash": hash_value(args_json)},
        )
    )


def log_egress_blocked(
    logger: Logger, run_id: str, url: str, reason: str
) -> None:
    logger.emit(
        AuditEvent(
            run_id=run_id,
            event="egress_blocked",
            severity=Severity.WARN,
            component="egress",
            reason=reason,
            attrs={"url": redact(url)},
        )
    )
