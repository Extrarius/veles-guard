# Illustrative examples for notes/part-9-ai-coding-security/28-coding-agent-permissions-sandbox-approval.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse


class Mode(str, Enum):
    READ_ONLY = "read_only"
    WORKSPACE_WRITE = "workspace_write"
    NETWORK_ALLOWED = "network_allowed"
    FULL_ACCESS = "danger_full_access"


class ActionType(str, Enum):
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    RUN_SHELL = "run_shell"
    NETWORK_CALL = "network_call"
    INSTALL_DEP = "install_dependency"
    EDIT_WORKFLOW = "edit_workflow"
    READ_SECRET = "read_secret"


@dataclass
class Action:
    type: ActionType
    path: str = ""
    command: str = ""
    url: str = ""


@dataclass
class Policy:
    mode: Mode
    workspace_root: str
    network_allowlist: list[str] = field(default_factory=list)

    def allow(self, action: Action) -> None:
        if action.type == ActionType.READ_FILE:
            self.validate_path(action.path)
            return

        if action.type == ActionType.WRITE_FILE:
            if self.mode not in (Mode.WORKSPACE_WRITE, Mode.NETWORK_ALLOWED, Mode.FULL_ACCESS):
                raise PermissionError("write denied in current mode")
            self.validate_path(action.path)
            return

        if action.type == ActionType.RUN_SHELL:
            if self.mode == Mode.READ_ONLY:
                raise PermissionError("shell denied in read-only mode")
            requires_approval("shell command requires approval")
            return

        if action.type == ActionType.NETWORK_CALL:
            if self.mode not in (Mode.NETWORK_ALLOWED, Mode.FULL_ACCESS):
                raise PermissionError("network denied in current mode")
            self.validate_url(action.url)
            return

        if action.type == ActionType.INSTALL_DEP:
            requires_approval("dependency install requires approval")
            return

        if action.type == ActionType.EDIT_WORKFLOW:
            raise PermissionError("CI workflow edit requires mandatory human review")

        if action.type == ActionType.READ_SECRET:
            raise PermissionError("secret read is blocked")

        raise ValueError("unknown action")

    def validate_path(self, path: str) -> None:
        root = os.path.abspath(self.workspace_root)
        clean = os.path.abspath(path)
        rel = os.path.relpath(clean, root)
        if rel.startswith("..") or os.path.isabs(rel):
            raise PermissionError("path escapes workspace")

    def validate_url(self, raw: str) -> None:
        parsed = urlparse(raw)
        if parsed.scheme != "https":
            raise ValueError("only https is allowed")
        host = (parsed.hostname or "").lower()
        for allowed in self.network_allowlist:
            if host == allowed or host.endswith("." + allowed):
                return
        raise PermissionError("network destination denied")


def requires_approval(reason: str) -> None:
    raise PermissionError(f"approval_required: {reason}")


ALLOWED_COMMANDS = {
    "go test ./...",
    "go vet ./...",
    "npm test",
    "npm run lint",
}


def validate_command(cmd: str) -> None:
    cmd = cmd.strip()

    if "curl " in cmd and "| sh" in cmd:
        raise ValueError("curl pipe shell is forbidden")

    if "rm -rf /" in cmd:
        raise ValueError("dangerous delete command")

    if cmd not in ALLOWED_COMMANDS:
        raise ValueError("command is not allowlisted")


class HookPhase(str, Enum):
    PRE = "pre"
    POST = "post"


def gate_hook(phase: HookPhase | str, hook_allow: bool, policy_allow: bool) -> None:
    """Stub: hook allow without policy → deny; post cannot undo."""
    if hook_allow and not policy_allow:
        raise PermissionError("deny: hook allow is not policy")
    p = phase.value if isinstance(phase, HookPhase) else phase
    if p == HookPhase.POST or p == "post":
        raise PermissionError("post hook cannot undo")
    if not policy_allow:
        raise PermissionError("deny: policy")


def _mode_rank(mode: str) -> int:
    ranks = {
        "read_only": 0,
        "default": 0,
        "workspace_write": 1,
        "acceptEdits": 1,
        "auto": 2,
        "network": 2,
        "bypass": 3,
        "bypassPermissions": 3,
        "danger_full_access": 3,
    }
    return ranks.get(mode, 1)


def gate_child(
    parent_tools: list[str],
    child_tools: list[str],
    parent_mode: str,
    child_mode: str,
) -> None:
    """Stub: child tools not ⊆ parent → deny; child mode wider → deny."""
    allow = set(parent_tools)
    for t in child_tools:
        if t not in allow:
            raise PermissionError("deny: child tool not in parent set")
    if _mode_rank(child_mode) > _mode_rank(parent_mode):
        raise PermissionError("deny: child mode wider than parent")
