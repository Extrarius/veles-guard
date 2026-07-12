# Illustrative examples for notes/part-3-processing-security/08-sandboxing.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field


@dataclass
class CommandPolicy:
    allowed_binaries: dict[str, bool]
    timeout: float = 5.0
    max_output_bytes: int = 64 * 1024
    work_dir: str = ""


def run_sandboxed_command(
    policy: CommandPolicy,
    name: str,
    *args: str,
) -> str:
    if not policy.allowed_binaries.get(name):
        raise ValueError("binary is not allowed")

    timeout = policy.timeout if policy.timeout > 0 else 5.0
    max_output = policy.max_output_bytes if policy.max_output_bytes > 0 else 64 * 1024

    # Важно: subprocess.run([name, *args], shell=False).
    # Не делать: subprocess.run("sh -c ...user input...", shell=True)
    result = subprocess.run(
        [name, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=policy.work_dir or None,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
        },
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr or "command failed")

    stdout = result.stdout or ""
    if len(stdout.encode("utf-8")) > max_output:
        stdout = stdout.encode("utf-8")[:max_output].decode("utf-8", errors="ignore")

    return stdout


# --- Sandbox policy для tool ---


@dataclass
class SandboxPolicy:
    enabled: bool = False
    network_allowed: bool = False
    allowed_hosts: list[str] = field(default_factory=list)
    read_only: bool = False
    max_input_bytes: int = 0
    max_output_bytes: int = 0
    max_duration_sec: int = 0
    requires_approval: bool = False


@dataclass
class ToolSpec:
    name: str
    action: str
    risk: str
    sandbox_policy: SandboxPolicy


TOOLS: dict[str, ToolSpec] = {
    "read_docs": ToolSpec(
        name="read_docs",
        action="read",
        risk="medium",
        sandbox_policy=SandboxPolicy(
            enabled=True,
            network_allowed=False,
            read_only=True,
            max_input_bytes=1 << 20,
            max_output_bytes=64 << 10,
            max_duration_sec=5,
        ),
    ),
    "run_code": ToolSpec(
        name="run_code",
        action="execute",
        risk="high",
        sandbox_policy=SandboxPolicy(
            enabled=True,
            network_allowed=False,
            read_only=False,
            max_input_bytes=128 << 10,
            max_output_bytes=64 << 10,
            max_duration_sec=3,
            requires_approval=True,
        ),
    ),
}
