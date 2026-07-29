# Illustrative examples for notes/part-10-course-appendix/33-course-ai-security-landscape.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations


def section_refs(layer: str) -> list[str]:
    """Map system layer to handbook section anchors (parts I–IX)."""
    mapping = {
        "interface": ["§03", "§04", "§05"],
        "app_control": ["§06", "§07", "§14", "§17"],
        "ai_knowledge": ["§04", "§09", "§11", "§12", "§13"],
        "execution": ["§08", "§18", "§19", "§22", "§28", "§31"],
        "assurance": ["§15", "§16", "§20", "§21", "§23"],
    }
    if layer not in mapping:
        raise ValueError(f"unknown layer {layer!r}")
    return list(mapping[layer])
