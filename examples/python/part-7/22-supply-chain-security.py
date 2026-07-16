# Illustrative examples for notes/part-7-testing-compliance/22-supply-chain-security.md
# Not for production use. Licensed under MIT (see LICENSE-CODE).

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class ArtifactType(str, Enum):
    DEPENDENCY = "dependency"
    CONTAINER = "container"
    PROMPT = "prompt"
    POLICY = "policy"
    TOOL = "tool"
    MCP_SERVER = "mcp_server"
    MODEL = "model"
    DATASET = "dataset"


@dataclass
class Artifact:
    name: str
    type: ArtifactType
    version: str
    hash: str = ""
    source: str = ""
    owner: str = ""
    reviewed: bool = False
    capabilities: List[str] = field(default_factory=list)


def validate_inventory(items: List[Artifact]) -> None:
    for item in items:
        if not item.name or not item.type or not item.version:
            raise ValueError("artifact has required empty fields")

        if not item.owner:
            raise ValueError(f"artifact has no owner: {item.name}")

        if not item.hash and item.type != ArtifactType.MODEL:
            raise ValueError(f"artifact has no hash: {item.name}")

        if _is_capability_artifact(item.type) and not item.reviewed:
            raise ValueError(f"capability artifact is not reviewed: {item.name}")


def _is_capability_artifact(artifact_type: ArtifactType) -> bool:
    return artifact_type in (
        ArtifactType.TOOL,
        ArtifactType.MCP_SERVER,
        ArtifactType.POLICY,
        ArtifactType.PROMPT,
    )


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_prompt_artifact(
    name: str, version: str, source: str, owner: str, content: bytes
) -> Artifact:
    return Artifact(
        name=name,
        type=ArtifactType.PROMPT,
        version=version,
        hash=hash_bytes(content),
        source=source,
        owner=owner,
        reviewed=True,
    )


@dataclass
class ToolSchema:
    name: str
    version: str
    schema: Dict[str, Any]
    hash: str


def compute_schema_hash(schema: Dict[str, Any]) -> str:
    encoded = json.dumps(schema, sort_keys=True).encode("utf-8")
    return hash_bytes(encoded)


def validate_tool_schema(tool_schema: ToolSchema) -> None:
    actual = compute_schema_hash(tool_schema.schema)
    if actual != tool_schema.hash:
        raise ValueError(f"tool schema hash mismatch: {tool_schema.name}")


@dataclass
class Allowlist:
    allowed: Dict[str, str]  # name -> hash

    def check(self, item: Artifact) -> None:
        expected_hash = self.allowed.get(item.name)
        if expected_hash is None:
            raise ValueError(f"artifact not allowlisted: {item.name}")

        if expected_hash != item.hash:
            raise ValueError(f"artifact hash mismatch: {item.name}")
