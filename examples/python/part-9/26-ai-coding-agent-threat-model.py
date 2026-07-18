# Illustrative examples for notes/part-9-ai-coding-security/26-ai-coding-agent-threat-model.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class CodingTask:
    id: str
    title: str
    files_touched: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    network: bool = False
    shell: bool = False
    dependencies: bool = False
    ci_changes: bool = False
    secrets_seen: bool = False


def classify_task(task: CodingTask) -> RiskLevel:
    if task.secrets_seen:
        return RiskLevel.CRITICAL
    if task.ci_changes or task.dependencies:
        return RiskLevel.HIGH
    if task.shell or task.network:
        return RiskLevel.HIGH
    if len(task.files_touched) > 10:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
