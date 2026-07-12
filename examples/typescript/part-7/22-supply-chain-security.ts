// Illustrative examples for notes/part-7-testing-compliance/22-supply-chain-security.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).
/// <reference path="../types.d.ts" />

import { createHash } from "node:crypto";

enum ArtifactType {
  Dependency = "dependency",
  Container = "container",
  Prompt = "prompt",
  Policy = "policy",
  Tool = "tool",
  MCPServer = "mcp_server",
  Model = "model",
  Dataset = "dataset",
}

interface Artifact {
  name: string;
  type: ArtifactType;
  version: string;
  hash: string;
  source: string;
  owner: string;
  reviewed: boolean;
  capabilities?: string[];
}

function validateInventory(items: Artifact[]): void {
  for (const item of items) {
    if (!item.name || !item.type || !item.version) {
      throw new Error("artifact has required empty fields");
    }

    if (!item.owner) {
      throw new Error(`artifact has no owner: ${item.name}`);
    }

    if (!item.hash && item.type !== ArtifactType.Model) {
      throw new Error(`artifact has no hash: ${item.name}`);
    }

    if (isCapabilityArtifact(item.type) && !item.reviewed) {
      throw new Error(`capability artifact is not reviewed: ${item.name}`);
    }
  }
}

function isCapabilityArtifact(artifactType: ArtifactType): boolean {
  return (
    artifactType === ArtifactType.Tool ||
    artifactType === ArtifactType.MCPServer ||
    artifactType === ArtifactType.Policy ||
    artifactType === ArtifactType.Prompt
  );
}

function hashBytes(data: string | Uint8Array): string {
  const input =
    typeof data === "string" ? data : new TextDecoder().decode(data);
  return createHash("sha256").update(input).digest("hex");
}

function newPromptArtifact(
  name: string,
  version: string,
  source: string,
  owner: string,
  content: Uint8Array,
): Artifact {
  return {
    name,
    type: ArtifactType.Prompt,
    version,
    hash: hashBytes(content),
    source,
    owner,
    reviewed: true,
  };
}

interface ToolSchema {
  name: string;
  version: string;
  schema: Record<string, unknown>;
  hash: string;
}

function computeSchemaHash(schema: Record<string, unknown>): string {
  return hashBytes(JSON.stringify(schema));
}

function validateToolSchema(toolSchema: ToolSchema): void {
  const actual = computeSchemaHash(toolSchema.schema);
  if (actual !== toolSchema.hash) {
    throw new Error(`tool schema hash mismatch: ${toolSchema.name}`);
  }
}

class Allowlist {
  allowed: Record<string, string>; // name -> hash

  constructor(allowed: Record<string, string>) {
    this.allowed = allowed;
  }

  check(item: Artifact): void {
    const expectedHash = this.allowed[item.name];
    if (!expectedHash) {
      throw new Error(`artifact not allowlisted: ${item.name}`);
    }

    if (expectedHash !== item.hash) {
      throw new Error(`artifact hash mismatch: ${item.name}`);
    }
  }
}
