# Illustrative examples for notes/part-9-ai-coding-security/29-ai-generated-code-review-spec-driven.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum


class Risk(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class ChangedFile:
    path: str
    additions: int = 0
    deletions: int = 0


def normalize_path(path: str) -> str:
    return os.path.normpath(path).replace("\\", "/")


def classify_file(path: str) -> Risk:
    p = normalize_path(path)

    if p.startswith(".github/workflows/"):
        return Risk.CRITICAL
    if p == "Dockerfile" or p.endswith(".Dockerfile"):
        return Risk.HIGH
    if p in ("package.json", "package-lock.json", "go.mod", "go.sum"):
        return Risk.HIGH
    if p in ("AGENTS.md", "CLAUDE.md") or p.startswith(".github/instructions/"):
        return Risk.HIGH
    if "auth" in p or "permission" in p or "policy" in p:
        return Risk.HIGH
    if p.endswith("_test.go") or "/test" in p:
        return Risk.MEDIUM

    return Risk.MEDIUM


@dataclass
class PullRequest:
    id: str
    author: str
    files: list[ChangedFile] = field(default_factory=list)
    agent_generated: bool = False
    approved_by_human: bool = False
    security_approved: bool = False
    ci_passed: bool = False
    security_scan_passed: bool = False


def requires_security_review(pr: PullRequest) -> bool:
    if pr.agent_generated:
        return True

    for file in pr.files:
        risk = classify_file(file.path)
        if risk in (Risk.HIGH, Risk.CRITICAL):
            return True

    return False


def can_merge(pr: PullRequest) -> bool:
    if not pr.approved_by_human:
        return False
    if not pr.ci_passed or not pr.security_scan_passed:
        return False
    if requires_security_review(pr) and not pr.security_approved:
        return False
    return True
