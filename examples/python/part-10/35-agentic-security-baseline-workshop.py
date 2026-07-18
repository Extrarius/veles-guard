# Illustrative examples for notes/part-10-course-appendix/35-agentic-security-baseline-workshop.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations


def reject_floating(version: str) -> None:
    """Reject empty or floating versions; pin an exact version instead."""
    v = version.strip().lower()
    if (
        not v
        or v == "latest"
        or v == "*"
        or v.startswith("^")
        or v.startswith("~")
    ):
        raise ValueError(f'floating or empty version "{version}" — pin exact version')
