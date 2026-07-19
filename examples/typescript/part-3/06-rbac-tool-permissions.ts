// Illustrative examples for notes/part-3-processing-security/06-rbac-tool-permissions.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum Risk {
  Low = "low",
  Medium = "medium",
  High = "high",
}

enum ToolAction {
  Read = "read",
  Write = "write",
  Delete = "delete",
  Execute = "execute",
  Send = "send",
}

enum Decision {
  Allow = "allow",
  Deny = "deny",
  RequireApproval = "require_approval",
}

interface Actor {
  userId: string;
  roles: string[];
  scopes: string[];
}

interface ToolCall {
  name: string;
  action: ToolAction;
  resource: string;
  args: Record<string, unknown>;
  risk: Risk;
}

interface Policy {
  decide(actor: Actor, call: ToolCall): Decision;
}

interface Tool {
  call(args: Record<string, unknown>): string;
}

interface AuditLogger {
  logDecision(actor: Actor, call: ToolCall, decision: Decision): void;
}

class SimplePolicy implements Policy {
  decide(actor: Actor, call: ToolCall): Decision {
    if (call.action === ToolAction.Delete || call.action === ToolAction.Execute) {
      return Decision.RequireApproval;
    }

    if (call.risk === Risk.High) {
      return Decision.RequireApproval;
    }

    const requiredScope = `${call.name}:${call.action}`;
    if (!hasScope(actor.scopes, requiredScope)) {
      return Decision.Deny;
    }

    return Decision.Allow;
  }
}

function hasScope(scopes: string[], required: string): boolean {
  return scopes.includes(required);
}

class Runtime {
  constructor(
    private policy: Policy,
    private tools: Map<string, Tool>,
    private audit: AuditLogger,
  ) {}

  executeTool(actor: Actor, call: ToolCall): string {
    const decision = this.policy.decide(actor, call);
    this.audit.logDecision(actor, call, decision);

    switch (decision) {
      case Decision.Deny:
        throw new Error("tool call denied");
      case Decision.RequireApproval:
        throw new Error("tool call requires human approval");
      case Decision.Allow: {
        const tool = this.tools.get(call.name);
        if (!tool) {
          throw new Error(`unknown tool: ${call.name}`);
        }
        return tool.call(call.args);
      }
      default:
        throw new Error("unknown policy decision");
    }
  }
}

// --- Agent Identity + Safe Tool Binding (see §06) ---

enum ActingMode {
  Own = "own_identity",
  OnBehalf = "on_behalf_of",
}

interface AgentPrincipal {
  id: string;
  owner: string;
  actingMode: ActingMode;
  baselineRole: string;
  onBehalfOf?: string;
  elevatedUntil?: Date;
  allowedTools: Record<string, boolean>;
}

function effectiveRole(agent: AgentPrincipal, now: Date): string {
  if (agent.elevatedUntil && now < agent.elevatedUntil) {
    return `${agent.baselineRole}:elevated`;
  }
  return agent.baselineRole;
}

/** Deny without identity/owner, delegated mode without user, or tool outside allowlist. */
function authorizeTool(agent: AgentPrincipal, tool: string, _now: Date): void {
  if (!agent.id || !agent.owner) {
    throw new Error("agent identity and human owner required");
  }
  if (agent.actingMode === ActingMode.OnBehalf && !agent.onBehalfOf) {
    throw new Error("on_behalf_of required for delegated acting mode");
  }
  if (!agent.allowedTools[tool]) {
    throw new Error(`tool "${tool}" not in agent allowlist`);
  }
}

export {
  Risk,
  ToolAction,
  Decision,
  SimplePolicy,
  Runtime,
  hasScope,
  ActingMode,
  effectiveRole,
  authorizeTool,
};

export type { Actor, ToolCall, Policy, Tool, AuditLogger, AgentPrincipal };
