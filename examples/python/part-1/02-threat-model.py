# Illustrative examples for notes/part-1-architecture-threats/02-threat-model.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class STRIDE(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class Status(str, Enum):
    OPEN = "open"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    NEEDS_OWNER = "needs-owner"


@dataclass
class Risk:
    id: str
    dfd_element: str
    layer: str
    stride: STRIDE
    scenario: str
    severity: Severity
    controls: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)
    status: Status = Status.OPEN


AGENT_RISKS: list[Risk] = [
    Risk(
        id="R-001",
        dfd_element="User Input",
        layer="input",
        stride=STRIDE.TAMPERING,
        scenario="User prompt attempts to override system instructions or change the agent goal.",
        severity=Severity.HIGH,
        controls=[
            "prompt injection detection",
            "context isolation",
            "intent validation",
        ],
        sections=["03", "14"],
        status=Status.OPEN,
    ),
    Risk(
        id="R-002",
        dfd_element="Uploaded Docs / Web / Email",
        layer="input",
        stride=STRIDE.TAMPERING,
        scenario="Indirect prompt injection hidden in retrieved content influences tool selection.",
        severity=Severity.HIGH,
        controls=[
            "treat retrieved content as data",
            "content sanitization",
            "tool approval",
        ],
        sections=["03", "09"],
        status=Status.OPEN,
    ),
    Risk(
        id="R-003",
        dfd_element="Tool Router",
        layer="processing",
        stride=STRIDE.ELEVATION_OF_PRIVILEGE,
        scenario="Agent calls a privileged tool outside its allowed role or scope.",
        severity=Severity.HIGH,
        controls=[
            "RBAC",
            "tool allowlist",
            "schema validation",
            "human approval",
        ],
        sections=["06", "07", "14"],
        status=Status.OPEN,
    ),
    Risk(
        id="R-004",
        dfd_element="Memory / Vector Store",
        layer="processing",
        stride=STRIDE.TAMPERING,
        scenario="Malicious instruction is stored in memory and reused in future sessions.",
        severity=Severity.HIGH,
        controls=[
            "memory isolation",
            "memory write policy",
            "context sanitization",
        ],
        sections=["09"],
        status=Status.OPEN,
    ),
    Risk(
        id="R-005",
        dfd_element="Output Validator",
        layer="output",
        stride=STRIDE.INFORMATION_DISCLOSURE,
        scenario="Final answer exposes secrets, internal prompts, credentials, or private context.",
        severity=Severity.HIGH,
        controls=[
            "output validation",
            "secret scanning",
            "PII redaction",
        ],
        sections=["04", "11", "13"],
        status=Status.OPEN,
    ),
    Risk(
        id="R-006",
        dfd_element="Agent Loop",
        layer="infrastructure",
        stride=STRIDE.DENIAL_OF_SERVICE,
        scenario="Agent repeatedly calls expensive tools or LLM API until quota or budget is exhausted.",
        severity=Severity.MEDIUM,
        controls=[
            "max steps",
            "timeouts",
            "quotas",
            "circuit breaker",
        ],
        sections=["05", "16", "17"],
        status=Status.OPEN,
    ),
]


# --- Минимальная проверка риск-реестра ---


def high_risks_without_controls(risks: list[Risk]) -> list[Risk]:
    return [
        risk
        for risk in risks
        if risk.severity == Severity.HIGH and len(risk.controls) == 0
    ]
