# Illustrative examples for notes/part-6-multi-agent-security/19-mcp-security.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Protocol
from urllib.parse import urlparse


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class MCPServer:
    id: str
    name: str
    version: str
    origin: str
    owner: str
    allowed_tools: List[str] = field(default_factory=list)
    allowed_domains: List[str] = field(default_factory=list)
    allowed_roots: List[str] = field(default_factory=list)
    risk: RiskLevel = RiskLevel.LOW
    reviewed: bool = False


@dataclass
class Registry:
    servers: Dict[str, MCPServer]

    def get(self, server_id: str) -> MCPServer:
        server = self.servers.get(server_id)
        if server is None:
            raise ValueError(f"mcp server is not allowlisted: {server_id}")
        if not server.reviewed:
            raise ValueError(f"mcp server is not reviewed: {server_id}")
        return server


@dataclass
class MCPToolCall:
    run_id: str
    user_id: str
    tenant_id: str
    server_id: str
    tool: str
    args: Dict[str, Any] = field(default_factory=dict)
    time: datetime = field(default_factory=datetime.utcnow)


def _contains(items: List[str], want: str) -> bool:
    return want in items


@dataclass
class Policy:
    registry: Registry

    def allow(self, call: MCPToolCall) -> MCPServer:
        server = self.registry.get(call.server_id)

        if not _contains(server.allowed_tools, call.tool):
            raise ValueError(
                f"tool {call.tool} is not allowed for server {call.server_id}"
            )

        if server.risk == RiskLevel.CRITICAL:
            raise RuntimeError("critical MCP server requires manual execution")

        return server


def validate_url(raw: str, allowed_domains: List[str]) -> None:
    parsed = urlparse(raw)
    if parsed.scheme != "https":
        raise ValueError("only https is allowed")

    host = (parsed.hostname or "").lower()
    for domain in allowed_domains:
        domain = domain.lower()
        if host == domain or host.endswith("." + domain):
            return

    raise ValueError(f"domain is not allowed: {host}")


def validate_path(path: str, allowed_roots: List[str]) -> None:
    clean = os.path.normpath(path)

    for root in allowed_roots:
        root_clean = os.path.normpath(root)
        try:
            rel = os.path.relpath(clean, root_clean)
        except ValueError:
            continue

        if rel == "." or (not rel.startswith("..") and not os.path.isabs(rel)):
            return

    raise ValueError(f"path is outside allowed roots: {path}")


class MCPClient(Protocol):
    def call_tool(
        self, server_id: str, tool: str, args: Dict[str, Any]
    ) -> Any: ...


class AuditLogger(Protocol):
    def log_mcp_call(
        self, call: MCPToolCall, decision: str, reason: str
    ) -> None: ...


@dataclass
class Executor:
    client: MCPClient
    policy: Policy
    audit: AuditLogger

    def call(self, call: MCPToolCall) -> Any:
        try:
            server = self.policy.allow(call)
        except Exception as exc:
            self.audit.log_mcp_call(call, "denied", str(exc))
            raise

        raw_url = call.args.get("url")
        if isinstance(raw_url, str):
            try:
                validate_url(raw_url, server.allowed_domains)
            except Exception as exc:
                self.audit.log_mcp_call(call, "denied", str(exc))
                raise

        raw_path = call.args.get("path")
        if isinstance(raw_path, str):
            try:
                validate_path(raw_path, server.allowed_roots)
            except Exception as exc:
                self.audit.log_mcp_call(call, "denied", str(exc))
                raise

        self.audit.log_mcp_call(call, "allowed", "policy passed")
        return self.client.call_tool(call.server_id, call.tool, call.args)
