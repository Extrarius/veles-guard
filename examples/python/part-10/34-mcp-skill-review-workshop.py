# Illustrative examples for notes/part-10-course-appendix/34-mcp-skill-review-workshop.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

# Учебные маркеры — не полный detector. В проде: отдельный review + policy.
HOSTILE_MARKERS = (
    "ignore previous",
    "system override",
    "do not tell the user",
)


def description_looks_hostile(desc: str) -> bool:
    lower = desc.lower()
    return any(marker in lower for marker in HOSTILE_MARKERS)
