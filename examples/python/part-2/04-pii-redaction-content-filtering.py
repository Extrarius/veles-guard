# Illustrative examples for notes/part-2-input-security/04-pii-redaction-content-filtering.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Pattern


class EntityType(str, Enum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SECRET = "SECRET"


@dataclass
class Entity:
    type: EntityType
    start: int
    end: int
    value: str


@dataclass
class Recognizer:
    type: EntityType
    pattern: Pattern[str]


RECOGNIZERS: List[Recognizer] = [
    Recognizer(
        type=EntityType.EMAIL,
        pattern=re.compile(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
        ),
    ),
    Recognizer(
        type=EntityType.PHONE,
        pattern=re.compile(r"(?i)(\+?\d[\d\s\-()]{8,}\d)"),
    ),
    Recognizer(
        type=EntityType.SECRET,
        pattern=re.compile(
            r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s]+"
        ),
    ),
]


def detect_entities(input_text: str) -> List[Entity]:
    entities: List[Entity] = []
    for recognizer in RECOGNIZERS:
        for match in recognizer.pattern.finditer(input_text):
            entities.append(
                Entity(
                    type=recognizer.type,
                    start=match.start(),
                    end=match.end(),
                    value=match.group(0),
                )
            )
    return entities


def redact(input_text: str, entities: List[Entity]) -> str:
    if not entities:
        return input_text

    # Простой вариант для конспекта: заменяем найденные значения.
    # В production лучше учитывать пересечения span'ов и сортировку по offset.
    output = input_text
    for entity in entities:
        replacement = f"[{entity.type.value}]"
        if entity.type == EntityType.SECRET:
            replacement = "[SECRET_REDACTED]"
        output = output.replace(entity.value, replacement)
    return output


class InputAction(str, Enum):
    ALLOW = "allow"
    MASK = "mask"
    BLOCK = "block"


@dataclass
class RedactionDecision:
    action: InputAction
    reason: str = ""
    entities: List[Entity] = field(default_factory=list)


def decide_redaction(input_text: str) -> RedactionDecision:
    entities = detect_entities(input_text)

    for entity in entities:
        if entity.type == EntityType.SECRET:
            return RedactionDecision(
                action=InputAction.BLOCK,
                reason="secret detected in input",
                entities=entities,
            )

    if entities:
        return RedactionDecision(
            action=InputAction.MASK,
            reason="PII detected; input should be masked before LLM/logs",
            entities=entities,
        )

    return RedactionDecision(action=InputAction.ALLOW)


@dataclass
class SanitizedInput:
    original_allowed: bool = True
    text: str = ""
    redacted: bool = False
    reason: str = ""


# Minimal local injection guard (full detector: 03-prompt-injection-detection.*).
_INJECTION_GUARD = re.compile(
    r"(?i)(ignore (all )?(previous|prior|system|developer) instructions|"
    r"(reveal|print|show|dump).*(system prompt|developer message|hidden instruction)|"
    r"(call|invoke|use).*(shell|exec|http|browser|email|delete|payment)|"
    r"(send|upload|exfiltrate).*(secret|token|api key|password|env))"
)


def _injection_blocked(input_text: str) -> tuple[bool, str]:
    if _INJECTION_GUARD.search(input_text.strip()):
        return False, "high-risk prompt injection signal detected"
    return True, ""


def sanitize_for_llm(input_text: str) -> SanitizedInput:
    allowed, reason = _injection_blocked(input_text)
    if not allowed:
        raise ValueError(f"prompt injection blocked: {reason}")

    decision = decide_redaction(input_text)

    if decision.action == InputAction.BLOCK:
        raise ValueError(f"input blocked: {decision.reason}")
    if decision.action == InputAction.MASK:
        return SanitizedInput(
            original_allowed=False,
            text=redact(input_text, decision.entities),
            redacted=True,
            reason=decision.reason,
        )
    return SanitizedInput(original_allowed=True, text=input_text)
