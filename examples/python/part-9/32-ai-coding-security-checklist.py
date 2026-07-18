# Illustrative examples for notes/part-9-ai-coding-security/32-ai-coding-security-checklist.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Status(str, Enum):
    YES = "Yes"
    PARTIAL = "Partial"
    NO = "No"
    NA = "N/A"


@dataclass
class Item:
    id: str
    title: str
    severity: Severity
    status: Status
    owner: str = ""
    evidence: list[str] = field(default_factory=list)
    reason: str = ""


def validate(items: list[Item]) -> None:
    for item in items:
        if not item.id or not item.title:
            raise ValueError("empty required fields")

        if item.severity in (Severity.CRITICAL, Severity.HIGH) and item.status == Status.NO:
            raise ValueError(f"blocking checklist item: {item.id}")

        if item.status == Status.PARTIAL and not item.owner:
            raise ValueError(f"partial item requires owner: {item.id}")

        if (
            item.status == Status.YES
            and item.severity in (Severity.CRITICAL, Severity.HIGH)
            and not item.evidence
        ):
            raise ValueError(f"high/critical item requires evidence: {item.id}")

        if item.status == Status.NA and not item.reason:
            raise ValueError(f"N/A requires reason: {item.id}")
