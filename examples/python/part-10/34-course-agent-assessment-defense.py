# Illustrative examples for notes/part-10-course-appendix/34-course-agent-assessment-defense.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations


def handbook_refs(area: str) -> list[str]:
    """Map assessment area to handbook section anchors."""
    mapping = {
        "input": ["§03"],
        "output": ["§04", "§11"],
        "knowledge": ["§09", "§13"],
        "tools_mcp": ["§06", "§14", "§19"],
        "assurance": ["§20", "§38"],
    }
    if area not in mapping:
        raise ValueError(f"unknown area {area!r}")
    return list(mapping[area])


def guardrail_assessment_hints() -> list[str]:
    """Course assessment questions (#guardrail-assessment); scoring stays in §20."""
    return [
        "ограничения (rails) на пути: input / retrieval / output / streaming?",
        "набор тестов (suite): легитимные (benign) + известные атаки (known-attack)?",
        "измерены ложные срабатывания / пропуски (FP / FN)?",
        "пороги зафиксированы (frozen) к прогону набора (suite run)?",
        "журнал изменений (changelog) при смене rail / threshold?",
        "агент может изготовить себе подтверждение (approval) / принять подделанное рассуждение (forged reasoning) за HITL? (§03/§14/§15; EV-12)",
    ]
