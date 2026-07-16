# Illustrative examples for notes/part-7-testing-compliance/21-compliance-standards.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List


class Status(str, Enum):
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    PLANNED = "planned"
    ACCEPTED_RISK = "accepted_risk"


@dataclass
class Control:
    id: str
    framework: str
    requirement: str
    control: str
    implementation: str
    evidence: List[str] = field(default_factory=list)
    owner: str = ""
    status: Status = Status.PLANNED
    review_date: datetime | None = None


CONTROLS: List[Control] = [
    Control(
        id="CTRL-001",
        framework="OWASP LLM01",
        requirement="Prompt Injection mitigation",
        control="Detect and isolate untrusted instructions",
        implementation="Input guard + context isolation + tool approval",
        evidence=["RT-001", "prompt_injection_detected logs"],
        owner="agent-runtime",
        status=Status.IMPLEMENTED,
    ),
    Control(
        id="CTRL-002",
        framework="OWASP LLM02",
        requirement="Sensitive information disclosure prevention",
        control="PII/secrets redaction before output and logs",
        implementation="Redaction pipeline + egress scanner",
        evidence=["redaction logs", "egress_blocked events"],
        owner="security",
        status=Status.PARTIAL,
    ),
    Control(
        id="CTRL-003",
        framework="NIST AI RMF Measure",
        requirement="Testing, evaluation, verification and validation",
        control="Adversarial regression suite",
        implementation="Red team cases in CI",
        evidence=["redteam-report.md", "CI run artifacts"],
        owner="platform",
        status=Status.PLANNED,
    ),
]


def validate_controls(controls: List[Control]) -> None:
    for control in controls:
        if not control.id or not control.framework or not control.control:
            raise ValueError("control has required empty fields")

        if not control.owner:
            raise ValueError(f"control has no owner: {control.id}")

        if control.status == Status.IMPLEMENTED and not control.evidence:
            raise ValueError(f"implemented control has no evidence: {control.id}")

        if control.status == Status.ACCEPTED_RISK and control.review_date is None:
            raise ValueError(f"accepted risk has no review date: {control.id}")


def export_json(controls: List[Control]) -> str:
    validate_controls(controls)
    payload = [
        {
            "id": c.id,
            "framework": c.framework,
            "requirement": c.requirement,
            "control": c.control,
            "implementation": c.implementation,
            "evidence": c.evidence,
            "owner": c.owner,
            "status": c.status.value,
            "review_date": c.review_date.isoformat() if c.review_date else None,
        }
        for c in controls
    ]
    return json.dumps(payload, indent=2)
