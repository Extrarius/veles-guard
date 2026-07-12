# Illustrative examples for notes/part-7-testing-compliance/23-incident-response-recovery.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class IncidentStatus(str, Enum):
    OPEN = "open"
    CONTAINED = "contained"
    RECOVERING = "recovering"
    RESOLVED = "resolved"


@dataclass
class Incident:
    id: str
    title: str
    severity: Severity
    status: IncidentStatus
    run_ids: List[str] = field(default_factory=list)
    affected_tools: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    data_types: List[str] = field(default_factory=list)
    detected_at: datetime | None = None
    owner: str = ""
    summary: str = ""


@dataclass
class Signal:
    event: str
    tool: str = ""
    run_id: str = ""
    attrs: Dict[str, str] = field(default_factory=dict)


def classify(signal: Signal) -> Severity:
    if signal.event in (
        "secret_exfiltrated",
        "cross_tenant_leakage",
        "production_shell_executed",
    ):
        return Severity.CRITICAL
    if signal.event in (
        "egress_with_secret_blocked",
        "mcp_server_compromised",
        "unsafe_tool_executed",
    ):
        return Severity.HIGH
    if signal.event in (
        "prompt_injection_detected",
        "tool_denied_repeated",
        "budget_exceeded",
    ):
        return Severity.MEDIUM
    return Severity.LOW


class ContainmentAction(str, Enum):
    STOP_RUN = "stop_run"
    DISABLE_TOOL = "disable_tool"
    BLOCK_EGRESS = "block_egress"
    ROTATE_SECRET = "rotate_secret"
    ISOLATE_MEMORY = "isolate_memory"
    READ_ONLY_MODE = "read_only_mode"
    DISABLE_MCP = "disable_mcp_server"


def build_containment_plan(signal: Signal) -> List[ContainmentAction]:
    if signal.event == "secret_exfiltrated":
        return [
            ContainmentAction.STOP_RUN,
            ContainmentAction.BLOCK_EGRESS,
            ContainmentAction.ROTATE_SECRET,
            ContainmentAction.DISABLE_TOOL,
        ]
    if signal.event == "mcp_server_compromised":
        return [
            ContainmentAction.DISABLE_MCP,
            ContainmentAction.BLOCK_EGRESS,
            ContainmentAction.ISOLATE_MEMORY,
        ]
    if signal.event == "memory_poisoning_detected":
        return [ContainmentAction.STOP_RUN, ContainmentAction.ISOLATE_MEMORY]
    if signal.event == "unsafe_tool_executed":
        return [
            ContainmentAction.STOP_RUN,
            ContainmentAction.DISABLE_TOOL,
            ContainmentAction.READ_ONLY_MODE,
        ]
    return [ContainmentAction.STOP_RUN]


def validate_incident(incident: Incident) -> None:
    if not incident.id or not incident.title or not incident.owner:
        raise ValueError("incident has required empty fields")

    if not incident.severity or not incident.status:
        raise ValueError("incident has no severity or status")

    if not incident.run_ids:
        raise ValueError("incident has no run ids")

    if incident.detected_at is None:
        raise ValueError("incident has no detected_at")


def export_incident(incident: Incident) -> str:
    validate_incident(incident)
    payload = {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "run_ids": incident.run_ids,
        "affected_tools": incident.affected_tools,
        "affected_users": incident.affected_users,
        "data_types": incident.data_types,
        "detected_at": incident.detected_at.isoformat() if incident.detected_at else None,
        "owner": incident.owner,
        "summary": incident.summary,
    }
    return json.dumps(payload, indent=2)
