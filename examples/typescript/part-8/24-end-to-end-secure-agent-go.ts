// Illustrative examples for notes/part-8-practice/24-end-to-end-secure-agent-go.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum RiskLevel {
  Low = "Low",
  Medium = "Medium",
  High = "High",
  Critical = "Critical",
}

enum TrustLevel {
  TrustedRuntime = "trusted_runtime",
  UntrustedUser = "untrusted_user",
  UntrustedTool = "untrusted_tool",
}

interface ToolCall {
  name: string;
  args: Record<string, unknown>;
}

interface Plan {
  finalAnswer?: string;
  toolCall?: ToolCall | null;
  reason?: string;
}

interface ContextBlock {
  source: string;
  trust: TrustLevel;
  text: string;
}

interface RunRequest {
  runId: string;
  userId: string;
  task: string;
}

interface RunResult {
  runId: string;
  finalAnswer?: string;
  toolCalls: ToolCall[];
  blocked: string[];
}

interface InputGuard {
  check(task: string): void;
}

interface ContextBuilder {
  build(req: RunRequest): ContextBlock[];
}

interface Planner {
  plan(req: RunRequest, blocks: ContextBlock[]): Plan;
}

interface Policy {
  allow(req: RunRequest, call: ToolCall): RiskLevel;
}

interface SchemaValidator {
  validate(call: ToolCall): void;
}

interface ApprovalGate {
  approve(req: RunRequest, call: ToolCall, risk: RiskLevel): void;
}

interface ToolExecutor {
  execute(call: ToolCall): string;
}

interface OutputValidator {
  validate(text: string): void;
}

interface AuditLogger {
  log(event: AuditEvent): void;
}

interface AuditEvent {
  time: Date;
  runId: string;
  userId?: string;
  event: string;
  component: string;
  tool?: string;
  risk?: RiskLevel;
  decision?: string;
  reason?: string;
  attrs?: Record<string, unknown>;
}

class Budget {
  maxSteps: number;
  maxToolCalls: number;
  maxDenied: number;
  steps = 0;
  toolCalls = 0;
  denied = 0;

  constructor(maxSteps: number, maxToolCalls: number, maxDenied: number) {
    this.maxSteps = maxSteps;
    this.maxToolCalls = maxToolCalls;
    this.maxDenied = maxDenied;
  }

  check(): void {
    if (this.steps > this.maxSteps) {
      throw new Error("budget exceeded: max steps");
    }
    if (this.toolCalls > this.maxToolCalls) {
      throw new Error("budget exceeded: max tool calls");
    }
    if (this.denied > this.maxDenied) {
      throw new Error("budget exceeded: max denied actions");
    }
  }
}

class Runtime {
  inputGuard: InputGuard;
  contextBuilder: ContextBuilder;
  planner: Planner;
  policy: Policy;
  schema: SchemaValidator;
  approval: ApprovalGate;
  executor: ToolExecutor;
  output: OutputValidator;
  audit: AuditLogger;
  budgetFactory: () => Budget;

  constructor(
    inputGuard: InputGuard,
    contextBuilder: ContextBuilder,
    planner: Planner,
    policy: Policy,
    schema: SchemaValidator,
    approval: ApprovalGate,
    executor: ToolExecutor,
    output: OutputValidator,
    audit: AuditLogger,
    budgetFactory: () => Budget,
  ) {
    this.inputGuard = inputGuard;
    this.contextBuilder = contextBuilder;
    this.planner = planner;
    this.policy = policy;
    this.schema = schema;
    this.approval = approval;
    this.executor = executor;
    this.output = output;
    this.audit = audit;
    this.budgetFactory = budgetFactory;
  }

  run(req: RunRequest): RunResult {
    if (!req.runId) {
      throw new Error("run_id is required");
    }

    const result: RunResult = { runId: req.runId, toolCalls: [], blocked: [] };
    const budget = this.budgetFactory();

    try {
      this.inputGuard.check(req.task);
    } catch (err) {
      this.audit.log({
        time: new Date(),
        runId: req.runId,
        userId: req.userId,
        event: "input_blocked",
        component: "input_guard",
        decision: "denied",
        reason: err instanceof Error ? err.message : String(err),
      });
      throw err;
    }

    let blocks = this.contextBuilder.build(req);

    while (true) {
      budget.steps += 1;
      try {
        budget.check();
      } catch (err) {
        result.blocked.push("budget_exceeded");
        throw err;
      }

      const plan = this.planner.plan(req, blocks);

      if (!plan.toolCall) {
        try {
          this.output.validate(plan.finalAnswer ?? "");
        } catch (err) {
          result.blocked.push("output_blocked");
          throw err;
        }

        result.finalAnswer = plan.finalAnswer ?? "";
        return result;
      }

      const call = plan.toolCall;
      budget.toolCalls += 1;

      let risk: RiskLevel;
      try {
        risk = this.policy.allow(req, call);
      } catch (err) {
        budget.denied += 1;
        result.blocked.push(`tool_denied:${call.name}`);
        this.audit.log({
          time: new Date(),
          runId: req.runId,
          userId: req.userId,
          event: "tool_denied",
          component: "policy",
          tool: call.name,
          decision: "denied",
          reason: err instanceof Error ? err.message : String(err),
        });
        throw err;
      }

      try {
        this.schema.validate(call);
      } catch (err) {
        budget.denied += 1;
        result.blocked.push(`schema_validation_failed:${call.name}`);
        throw err;
      }

      if (requiresApproval(risk)) {
        try {
          this.approval.approve(req, call, risk);
        } catch (err) {
          budget.denied += 1;
          result.blocked.push(`approval_rejected:${call.name}`);
          throw err;
        }
      }

      const observation = this.executor.execute(call);
      result.toolCalls.push(call);

      blocks = [
        ...blocks,
        {
          source: `tool:${call.name}`,
          trust: TrustLevel.UntrustedTool,
          text: observation,
        },
      ];
    }
  }
}

function requiresApproval(risk: RiskLevel): boolean {
  return risk === RiskLevel.High || risk === RiskLevel.Critical;
}

class Guard implements InputGuard {
  maxChars: number;

  constructor(maxChars: number) {
    this.maxChars = maxChars;
  }

  check(task: string): void {
    if (!task.trim()) {
      throw new Error("empty task");
    }

    if (task.length > this.maxChars) {
      throw new Error("input too large");
    }

    const lower = task.toLowerCase();
    const suspicious = [
      "ignore previous instructions",
      "disregard system prompt",
      "reveal your system prompt",
      "send secrets",
      "exfiltrate",
    ];

    for (const marker of suspicious) {
      if (lower.includes(marker)) {
        throw new Error("possible prompt injection");
      }
    }
  }
}

interface Memory {
  readForUser(userId: string): ContextBlock[];
}

class Builder implements ContextBuilder {
  memory: Memory;

  constructor(memory: Memory) {
    this.memory = memory;
  }

  build(req: RunRequest): ContextBlock[] {
    const memoryBlocks = this.memory.readForUser(req.userId);
    return [
      {
        source: "user_task",
        trust: TrustLevel.UntrustedUser,
        text: req.task,
      },
      ...memoryBlocks,
    ];
  }
}

enum UserRole {
  Reader = "reader",
  Writer = "writer",
  Admin = "admin",
}

interface User {
  id: string;
  role: UserRole;
  tools: string[];
}

interface UserStore {
  getUser(userId: string): User;
}

class PolicyEngine implements Policy {
  users: UserStore;

  constructor(users: UserStore) {
    this.users = users;
  }

  allow(req: RunRequest, call: ToolCall): RiskLevel {
    const user = this.users.getUser(req.userId);

    if (!contains(user.tools, call.name)) {
      throw new Error(`tool not allowed for user: ${call.name}`);
    }

    if (call.name === "search_docs") {
      return RiskLevel.Low;
    }

    if (call.name === "send_email" || call.name === "delete_file" || call.name === "run_shell") {
      if (user.role !== UserRole.Admin) {
        throw new Error("high-risk tool requires admin role");
      }
      return RiskLevel.High;
    }

    throw new Error("unknown tool");
  }
}

class ToolSchemaValidator implements SchemaValidator {
  allowedArgs: Record<string, string[]>;

  constructor(allowedArgs: Record<string, string[]>) {
    this.allowedArgs = allowedArgs;
  }

  validate(call: ToolCall): void {
    const allowed = this.allowedArgs[call.name];
    if (!allowed) {
      throw new Error(`schema not found for tool: ${call.name}`);
    }

    for (const key of Object.keys(call.args)) {
      if (!contains(allowed, key)) {
        throw new Error(`unexpected arg "${key}" for tool ${call.name}`);
      }
    }

    if (call.name === "search_docs") {
      const query = call.args.query;
      if (typeof query !== "string" || !query) {
        throw new Error("search_docs.query is required");
      }
    }
  }
}

interface Tool {
  call(args: Record<string, unknown>): string;
}

class Registry {
  tools: Record<string, Tool>;

  constructor(tools: Record<string, Tool>) {
    this.tools = tools;
  }

  get(name: string): Tool {
    const tool = this.tools[name];
    if (!tool) {
      throw new Error(`tool not registered: ${name}`);
    }
    return tool;
  }
}

class Executor implements ToolExecutor {
  registry: Registry;
  audit: AuditLogger;

  constructor(registry: Registry, audit: AuditLogger) {
    this.registry = registry;
    this.audit = audit;
  }

  execute(call: ToolCall): string {
    const tool = this.registry.get(call.name);
    return tool.call(call.args);
  }
}

const secretPatterns = [
  /api[_-]?key\s*[:=]\s*['"]?[^'"\s]+/i,
  /bearer\s+[a-z0-9._\-]+/i,
];

class OutputValidatorImpl implements OutputValidator {
  validate(text: string): void {
    for (const pattern of secretPatterns) {
      if (pattern.test(text)) {
        throw new Error("output contains possible secret");
      }
    }
  }
}

function newRuntime(
  inputGuard: InputGuard,
  contextBuilder: ContextBuilder,
  planner: Planner,
  policy: Policy,
  schema: SchemaValidator,
  approval: ApprovalGate,
  executor: ToolExecutor,
  output: OutputValidator,
  audit: AuditLogger,
): Runtime {
  return new Runtime(
    inputGuard,
    contextBuilder,
    planner,
    policy,
    schema,
    approval,
    executor,
    output,
    audit,
    () => new Budget(8, 4, 2),
  );
}

function contains(items: string[], want: string): boolean {
  return items.includes(want);
}
