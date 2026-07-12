# Illustrative examples for notes/part-8-practice/25-security-by-design-checklist.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
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
    evidence: list[str] = field(default_factory=list)
    owner: str = ""
    review_date: datetime = field(default_factory=lambda: datetime.min)
    reason: str = ""


def validate(items: list[Item]) -> None:
    for item in items:
        if not item.id or not item.title:
            raise ValueError("checklist item has required empty fields")

        if not item.severity or not item.status:
            raise ValueError(f"checklist item has no severity or status: {item.id}")

        if item.severity == Severity.HIGH and item.status == Status.YES and not item.evidence:
            raise ValueError(f"high severity item marked Yes without evidence: {item.id}")

        if item.severity == Severity.HIGH and item.status == Status.NO:
            raise ValueError(f"high severity item is No and blocks release: {item.id}")

        if item.status == Status.PARTIAL and not item.owner:
            raise ValueError(f"partial item has no owner: {item.id}")

        if item.status == Status.NA and not item.reason:
            raise ValueError(f"N/A item requires reason: {item.id}")


def export(items: list[Item]) -> str:
    validate(items)
    payload: list[dict[str, Any]] = []
    for item in items:
        row = asdict(item)
        row["severity"] = item.severity.value
        row["status"] = item.status.value
        if item.review_date != datetime.min:
            row["review_date"] = item.review_date.isoformat()
        else:
            row.pop("review_date", None)
        payload.append(row)
    return json.dumps(payload, indent=2)
