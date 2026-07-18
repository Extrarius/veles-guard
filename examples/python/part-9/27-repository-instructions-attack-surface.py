# Illustrative examples for notes/part-9-ai-coding-security/27-repository-instructions-attack-surface.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import os
from enum import Enum


class Trust(str, Enum):
    TRUSTED_INSTRUCTION = "trusted_instruction"
    UNTRUSTED_CONTEXT = "untrusted_context"
    HIGH_RISK_CONFIG = "high_risk_config"


FORBIDDEN_INSTRUCTION_MARKERS = [
    "ignore security policy",
    "disable approval",
    "turn off sandbox",
    "run with full access",
    "print secrets",
    "bypass egress",
    "disable tests",
    "remove security check",
]


def normalize_path(path: str) -> str:
    return os.path.normpath(path).replace("\\", "/")


def classify_path(path: str) -> Trust:
    clean = normalize_path(path)

    if clean == "AGENTS.md" or clean.endswith("/AGENTS.md"):
        return Trust.TRUSTED_INSTRUCTION
    if clean in ("CLAUDE.md", "GEMINI.md"):
        return Trust.TRUSTED_INSTRUCTION
    if clean == ".github/copilot-instructions.md":
        return Trust.TRUSTED_INSTRUCTION
    if clean.startswith(".github/instructions/") and clean.endswith(".instructions.md"):
        return Trust.TRUSTED_INSTRUCTION
    if clean.startswith(".github/workflows/"):
        return Trust.HIGH_RISK_CONFIG
    if clean in ("go.mod", "go.sum", "package.json") or clean.endswith("lock"):
        return Trust.HIGH_RISK_CONFIG

    return Trust.UNTRUSTED_CONTEXT


def validate_instruction_text(text: str) -> None:
    lower = text.lower()
    for marker in FORBIDDEN_INSTRUCTION_MARKERS:
        if marker in lower:
            raise ValueError(f"instruction attempts to override security policy: {marker}")
