# Illustrative examples for notes/part-10-course-appendix/33-course-appendix-agentic-security.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

ALLOWED = {
    "read_file": True,
    "repo_search": True,
}


def authorize(tool: str) -> None:
    """Deny by default: tool must be in the allowlist."""
    if not ALLOWED.get(tool, False):
        raise PermissionError(f'tool "{tool}" not in allowlist')
