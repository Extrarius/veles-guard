# Illustrative examples for notes/part-10-course-appendix/36-ai-agent-security-testing-workshop.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

from dataclasses import dataclass


CRITICAL = "Critical"
HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    area: str
    expected: str
    actual: str
    fix: str = ""
    regression_test: str = ""


def validate(f: Finding) -> None:
    """Reject incomplete findings; Critical/High require a regression test."""
    if not f.id or not f.title:
        raise ValueError("id and title required")
    if not f.area or not f.severity:
        raise ValueError("area and severity required")
    if not f.expected or not f.actual:
        raise ValueError("expected and actual required")
    if f.severity in (CRITICAL, HIGH) and not f.regression_test:
        raise ValueError(f"{f.severity} finding requires regression test")
