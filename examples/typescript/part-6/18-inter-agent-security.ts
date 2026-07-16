// Illustrative examples for notes/part-6-multi-agent-security/18-inter-agent-security.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

type AgentID = string;

enum Scope {
  ReadDocs = "read:docs",
  WebSearch = "web:search",
  SendEmail = "send:email",
  DBWrite = "db:write",
  ShellRun = "shell:run",
}

interface AgentIdentity {
  id: AgentID;
  role: string;
  allowedTools: string[];
  allowedScopes: Scope[];
  handoffTargets: AgentID[];
  promptVersion: string;
  policyVersion: string;
}

function hasScope(scopes: Scope[], want: Scope): boolean {
  return scopes.includes(want);
}

enum TrustLevel {
  TrustedRuntime = "trusted_runtime",
  UntrustedInput = "untrusted_input",
  AgentOutput = "agent_output",
}

interface AgentMessage {
  id: string;
  runId: string;
  parentActionId: string;
  from: AgentID;
  to: AgentID;
  task: string;
  dataRefs: string[];
  delegatedScopes: Scope[];
  trust: TrustLevel;
  createdAt: Date;
}

class HandoffPolicy {
  agents: Record<AgentID, AgentIdentity>;

  constructor(agents: Record<AgentID, AgentIdentity>) {
    this.agents = agents;
  }

  allowHandoff(msg: AgentMessage): void {
    const from = this.agents[msg.from];
    if (!from) {
      throw new Error(`unknown source agent: ${msg.from}`);
    }

    const to = this.agents[msg.to];
    if (!to) {
      throw new Error(`unknown target agent: ${msg.to}`);
    }

    if (!containsAgent(from.handoffTargets, msg.to)) {
      throw new Error(`handoff from ${msg.from} to ${msg.to} is not allowed`);
    }

    for (const scope of msg.delegatedScopes) {
      if (!hasScope(from.allowedScopes, scope)) {
        throw new Error(`source agent does not own scope: ${scope}`);
      }
      if (!hasScope(to.allowedScopes, scope)) {
        throw new Error(`target agent cannot receive scope: ${scope}`);
      }
    }

    if (msg.trust === TrustLevel.UntrustedInput) {
      throw new Error("untrusted input cannot be delegated without sanitization");
    }
  }
}

function containsAgent(items: AgentID[], want: AgentID): boolean {
  return items.includes(want);
}

class HandoffBudget {
  maxDepth: number;
  maxHandoffs: number;
  maxAgents: number;
  depth = 0;
  handoffs = 0;
  agentsInvolved: Record<AgentID, boolean> = {};

  constructor(maxDepth: number, maxHandoffs: number, maxAgents: number) {
    this.maxDepth = maxDepth;
    this.maxHandoffs = maxHandoffs;
    this.maxAgents = maxAgents;
  }

  check(next: AgentID): void {
    this.handoffs += 1;
    this.agentsInvolved[next] = true;

    if (this.depth > this.maxDepth) {
      throw new Error("max handoff depth exceeded");
    }
    if (this.handoffs > this.maxHandoffs) {
      throw new Error("max handoffs exceeded");
    }
    if (Object.keys(this.agentsInvolved).length > this.maxAgents) {
      throw new Error("max agents involved exceeded");
    }
  }
}

interface Agent {
  run(msg: AgentMessage): AgentMessage;
}

interface AuditLogger {
  logHandoff(msg: AgentMessage, decision: string, reason: string): void;
}

class HandoffExecutor {
  policy: HandoffPolicy;
  agents: Record<AgentID, Agent>;
  audit: AuditLogger;
  budget: HandoffBudget;

  constructor(
    policy: HandoffPolicy,
    agents: Record<AgentID, Agent>,
    audit: AuditLogger,
    budget: HandoffBudget,
  ) {
    this.policy = policy;
    this.agents = agents;
    this.audit = audit;
    this.budget = budget;
  }

  execute(msg: AgentMessage): AgentMessage {
    try {
      this.budget.check(msg.to);
    } catch (err) {
      this.audit.logHandoff(msg, "denied", String(err));
      throw err;
    }

    try {
      this.policy.allowHandoff(msg);
    } catch (err) {
      this.audit.logHandoff(msg, "denied", String(err));
      throw err;
    }

    const agent = this.agents[msg.to];
    if (!agent) {
      const reason = `agent not registered: ${msg.to}`;
      this.audit.logHandoff(msg, "denied", reason);
      throw new Error(reason);
    }

    this.audit.logHandoff(msg, "allowed", "handoff policy passed");
    return agent.run(msg);
  }
}
