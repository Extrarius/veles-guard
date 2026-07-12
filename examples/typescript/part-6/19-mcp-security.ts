// Illustrative examples for notes/part-6-multi-agent-security/19-mcp-security.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum RiskLevel {
  Low = "Low",
  Medium = "Medium",
  High = "High",
  Critical = "Critical",
}

interface MCPServer {
  id: string;
  name: string;
  version: string;
  origin: string;
  owner: string;
  allowedTools: string[];
  allowedDomains: string[];
  allowedRoots: string[];
  risk: RiskLevel;
  reviewed: boolean;
}

class Registry {
  servers: Record<string, MCPServer>;

  constructor(servers: Record<string, MCPServer>) {
    this.servers = servers;
  }

  get(serverId: string): MCPServer {
    const server = this.servers[serverId];
    if (!server) {
      throw new Error(`mcp server is not allowlisted: ${serverId}`);
    }
    if (!server.reviewed) {
      throw new Error(`mcp server is not reviewed: ${serverId}`);
    }
    return server;
  }
}

interface MCPToolCall {
  runId: string;
  userId: string;
  tenantId: string;
  serverId: string;
  tool: string;
  args: Record<string, unknown>;
  time: Date;
}

function contains(items: string[], want: string): boolean {
  return items.includes(want);
}

class Policy {
  registry: Registry;

  constructor(registry: Registry) {
    this.registry = registry;
  }

  allow(call: MCPToolCall): MCPServer {
    const server = this.registry.get(call.serverId);

    if (!contains(server.allowedTools, call.tool)) {
      throw new Error(
        `tool ${call.tool} is not allowed for server ${call.serverId}`,
      );
    }

    if (server.risk === RiskLevel.Critical) {
      throw new Error("critical MCP server requires manual execution");
    }

    return server;
  }
}

function validateURL(raw: string, allowedDomains: string[]): void {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch (err) {
    throw err;
  }

  if (parsed.protocol !== "https:") {
    throw new Error("only https is allowed");
  }

  const host = parsed.hostname.toLowerCase();
  for (const domain of allowedDomains) {
    const normalized = domain.toLowerCase();
    if (host === normalized || host.endsWith(`.${normalized}`)) {
      return;
    }
  }

  throw new Error(`domain is not allowed: ${host}`);
}

// Illustrative path normalization (no node:path). Production: use a vetted library.
function normalizePath(path: string): string {
  const isAbsolute = path.startsWith("/") || /^[A-Za-z]:[\\/]/.test(path);
  const segments = path.replace(/\\/g, "/").split("/");
  const stack: string[] = [];

  for (const segment of segments) {
    if (segment === "" || segment === ".") {
      continue;
    }
    if (segment === "..") {
      if (stack.length > 0) {
        stack.pop();
      }
      continue;
    }
    stack.push(segment);
  }

  const joined = stack.join("/");
  if (isAbsolute) {
    return `/${joined}`;
  }
  return joined;
}

function isWithinRoot(clean: string, rootClean: string): boolean {
  if (clean === rootClean) {
    return true;
  }
  const prefix = rootClean.endsWith("/") ? rootClean : `${rootClean}/`;
  return clean.startsWith(prefix);
}

function validatePath(path: string, allowedRoots: string[]): void {
  const clean = normalizePath(path);

  for (const root of allowedRoots) {
    const rootClean = normalizePath(root);
    if (isWithinRoot(clean, rootClean)) {
      return;
    }
  }

  throw new Error(`path is outside allowed roots: ${path}`);
}

interface MCPClient {
  callTool(serverId: string, tool: string, args: Record<string, unknown>): unknown;
}

interface AuditLogger {
  logMCPCall(call: MCPToolCall, decision: string, reason: string): void;
}

class Executor {
  client: MCPClient;
  policy: Policy;
  audit: AuditLogger;

  constructor(client: MCPClient, policy: Policy, audit: AuditLogger) {
    this.client = client;
    this.policy = policy;
    this.audit = audit;
  }

  call(call: MCPToolCall): unknown {
    let server: MCPServer;
    try {
      server = this.policy.allow(call);
    } catch (err) {
      this.audit.logMCPCall(call, "denied", String(err));
      throw err;
    }

    const rawURL = call.args.url;
    if (typeof rawURL === "string") {
      try {
        validateURL(rawURL, server.allowedDomains);
      } catch (err) {
        this.audit.logMCPCall(call, "denied", String(err));
        throw err;
      }
    }

    const rawPath = call.args.path;
    if (typeof rawPath === "string") {
      try {
        validatePath(rawPath, server.allowedRoots);
      } catch (err) {
        this.audit.logMCPCall(call, "denied", String(err));
        throw err;
      }
    }

    this.audit.logMCPCall(call, "allowed", "policy passed");
    return this.client.callTool(call.serverId, call.tool, call.args);
  }
}

const CONTROL_PHRASES = [
  "ignore previous",
  "call tool",
  "run command",
  "execute",
  "system:",
];

function validateToolOutput(raw: string, maxLen: number): string {
  if (raw.length > maxLen) {
    throw new Error(`tool output exceeds max length: ${maxLen}`);
  }

  const lower = raw.toLowerCase();
  for (const phrase of CONTROL_PHRASES) {
    if (lower.includes(phrase)) {
      throw new Error(`tool output contains control instruction: ${JSON.stringify(phrase)}`);
    }
  }

  return raw;
}
