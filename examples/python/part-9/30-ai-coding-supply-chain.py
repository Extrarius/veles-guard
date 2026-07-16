# Illustrative examples for notes/part-9-ai-coding-security/30-ai-coding-supply-chain.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum


class ChangeKind(str, Enum):
    DEPENDENCY_CHANGE = "dependency_change"
    CI_CHANGE = "ci_change"
    DOCKER_CHANGE = "docker_change"
    INSTRUCTION_CHANGE = "instruction_change"
    MCP_CHANGE = "mcp_change"
    SKILL_CHANGE = "skill_change"
    REGULAR_CODE = "regular_code"


def normalize_path(path: str) -> str:
    return os.path.normpath(path).replace("\\", "/")


def classify_change(path: str) -> ChangeKind:
    p = normalize_path(path)

    if p in (
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "go.mod",
        "go.sum",
        "requirements.txt",
        "poetry.lock",
    ):
        return ChangeKind.DEPENDENCY_CHANGE
    if p == "Dockerfile":
        return ChangeKind.DOCKER_CHANGE
    if p in ("AGENTS.md", "CLAUDE.md", "GEMINI.md"):
        return ChangeKind.INSTRUCTION_CHANGE
    if p.startswith(".github/workflows/"):
        return ChangeKind.CI_CHANGE
    if p.startswith(".mcp/"):
        return ChangeKind.MCP_CHANGE
    if p.startswith(".skills/"):
        return ChangeKind.SKILL_CHANGE

    return ChangeKind.REGULAR_CODE


@dataclass
class ChangedFile:
    path: str


@dataclass
class ReviewDecision:
    human_approved: bool = False
    security_approved: bool = False
    scanners_passed: bool = False
    sbom_updated: bool = False


def blocks_release(files: list[ChangedFile], decision: ReviewDecision) -> bool:
    high_risk = False

    for file in files:
        kind = classify_change(file.path)
        if kind in (
            ChangeKind.DEPENDENCY_CHANGE,
            ChangeKind.CI_CHANGE,
            ChangeKind.DOCKER_CHANGE,
            ChangeKind.INSTRUCTION_CHANGE,
            ChangeKind.MCP_CHANGE,
            ChangeKind.SKILL_CHANGE,
        ):
            high_risk = True

    if not decision.scanners_passed:
        return True
    if high_risk and not decision.security_approved:
        return True
    if high_risk and not decision.human_approved:
        return True
    if high_risk and not decision.sbom_updated:
        return True

    return False
