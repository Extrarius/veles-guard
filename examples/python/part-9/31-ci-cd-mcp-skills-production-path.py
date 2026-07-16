# Illustrative examples for notes/part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import os
from dataclasses import dataclass, field


def normalize_path(path: str) -> str:
    return os.path.normpath(path).replace("\\", "/")


def is_production_path(path: str) -> bool:
    p = normalize_path(path)

    if p.startswith(".github/workflows/"):
        return True
    if p.startswith("deploy/") or p.startswith("k8s/") or p.startswith("helm/"):
        return True
    if p == "Dockerfile" or p.endswith(".Dockerfile"):
        return True
    if "terraform" in p or p.endswith(".tf"):
        return True
    if p == "CODEOWNERS" or p.endswith("/CODEOWNERS"):
        return True

    return False


@dataclass
class PR:
    id: str
    agent_generated: bool = False
    changed_files: list[str] = field(default_factory=list)
    human_approved: bool = False
    security_approved: bool = False
    required_checks_ok: bool = False


def needs_production_review(pr: PR) -> bool:
    if pr.agent_generated:
        return True
    for path in pr.changed_files:
        if is_production_path(path):
            return True
    return False


def can_enter_production_path(pr: PR) -> bool:
    if not pr.required_checks_ok:
        return False
    if needs_production_review(pr) and not pr.human_approved:
        return False
    if needs_production_review(pr) and not pr.security_approved:
        return False
    return True
