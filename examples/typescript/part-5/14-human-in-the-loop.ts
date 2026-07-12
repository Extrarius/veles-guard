// Illustrative examples for notes/part-5-control-observability/14-human-in-the-loop.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum RiskLevel {
  Low = "Low",
  Medium = "Medium",
  High = "High",
  Critical = "Critical",
}

interface ToolAction {
  id: string;
  runId: string;
  tool: string;
  args: Record<string, unknown>;
  risk: RiskLevel;
  reason: string;
  createdAt: Date;
}

enum Decision {
  Approved = "approved",
  Rejected = "rejected",
  TimedOut = "timed_out",
}

interface ApprovalDecision {
  actionId: string;
  decision: Decision;
  approverId: string;
  reason: string;
  decidedAt: Date;
}

interface ApprovalService {
  requestApproval(action: ToolAction): ApprovalDecision;
}

interface AuditLogger {
  logApprovalRequested(action: ToolAction): void;
  logApprovalDecision(decision: ApprovalDecision): void;
  logToolExecuted(action: ToolAction, result: unknown): void;
}

interface Tool {
  call(args: Record<string, unknown>): unknown;
}

class Runtime {
  tools: Record<string, Tool>;
  approval: ApprovalService;
  audit: AuditLogger;

  constructor(tools: Record<string, Tool>, approval: ApprovalService, audit: AuditLogger) {
    this.tools = tools;
    this.approval = approval;
    this.audit = audit;
  }

  execute(action: ToolAction): unknown {
    const tool = this.tools[action.tool];
    if (!tool) {
      throw new Error(`unknown tool: ${action.tool}`);
    }

    if (requiresApproval(action)) {
      this.audit.logApprovalRequested(action);
      const decision = this.approval.requestApproval(action);
      this.audit.logApprovalDecision(decision);

      if (decision.decision !== Decision.Approved) {
        throw new Error("tool action was not approved");
      }
    }

    const result = tool.call(action.args);
    this.audit.logToolExecuted(action, result);
    return result;
  }
}

function requiresApproval(action: ToolAction): boolean {
  return action.risk === RiskLevel.High || action.risk === RiskLevel.Critical;
}

function classifyAction(
  tool: string,
  args: Record<string, unknown>,
): [RiskLevel, string] {
  switch (tool) {
    case "send_email":
    case "publish_post":
    case "delete_file":
    case "run_shell":
      return [RiskLevel.High, "external side effect or destructive action"];
    case "search_docs":
    case "read_public_page":
      return [RiskLevel.Low, "read-only action"];
    case "query_database":
      if (args.readonly === true) {
        return [RiskLevel.Medium, "internal data access"];
      }
      return [RiskLevel.High, "database write operation"];
    default:
      return [RiskLevel.High, "unknown tool requires explicit approval"];
  }
}
