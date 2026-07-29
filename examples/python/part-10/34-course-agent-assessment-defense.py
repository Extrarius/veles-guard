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
