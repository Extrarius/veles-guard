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


# --- PR/issue as untrusted input (#pr-issue-untrusted-input) ---


@dataclass
class PRReviewInput:
    title: str = ""
    body: str = ""
    comments: str = ""


def wrap_untrusted(label: str, text: str) -> str:
    """Explicit data frame; content is not policy/instructions."""
    return f'BEGIN_UNTRUSTED_DATA label="{label}"\n{text}\nEND_UNTRUSTED_DATA\n'


def scan_pr_text(s: str) -> list[str]:
    """Heuristic hits only — not the §03 detector pipeline."""
    lower = s.lower()
    hits: list[str] = []
    for p in (
        "ignore previous",
        "ignore all previous",
        "disregard previous",
        "system prompt",
        "you are now",
        "do not follow",
    ):
        if p in lower:
            hits.append(f"instruction_override:{p}")
    for ch in ("\u200b", "\u200c", "\u200d", "\ufeff"):
        if ch in s:
            hits.append("hidden_or_format_char")
            break
    return hits


def prepare_review_context(inp: PRReviewInput) -> tuple[str, list[str]]:
    raw = "\n".join(part for part in (inp.title, inp.body, inp.comments) if part).strip()
    hits = scan_pr_text(raw)
    return wrap_untrusted("pr_or_issue", raw), hits
