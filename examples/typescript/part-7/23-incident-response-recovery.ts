// Illustrative examples for notes/part-7-testing-compliance/23-incident-response-recovery.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum Severity {
  Critical = "Critical",
  High = "High",
  Medium = "Medium",
  Low = "Low",
}

enum IncidentStatus {
  Open = "open",
  Contained = "contained",
  Recovering = "recovering",
  Resolved = "resolved",
}

interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  runIds: string[];
  affectedTools: string[];
  affectedUsers: string[];
  dataTypes: string[];
  detectedAt: Date;
  owner: string;
  summary: string;
}

interface Signal {
  event: string;
  tool: string;
  runId: string;
  attrs: Record<string, string>;
}

function classify(signal: Signal): Severity {
  switch (signal.event) {
    case "secret_exfiltrated":
    case "cross_tenant_leakage":
    case "production_shell_executed":
    case "credential_use_after_revoke":
      return Severity.Critical;
    case "egress_with_secret_blocked":
    case "mcp_server_compromised":
    case "unsafe_tool_executed":
    case "egress_destination_out_of_policy":
    case "undeclared_tool_call":
    case "audit_gap":
    case "score_spike_after_network":
      return Severity.High;
    case "prompt_injection_detected":
    case "tool_denied_repeated":
    case "budget_exceeded":
    case "tool_retry_after_deny":
    case "eval_probe_suspected":
      return Severity.Medium;
    default:
      return Severity.Low;
  }
}

enum ContainmentAction {
  StopRun = "stop_run",
  DisableTool = "disable_tool",
  BlockEgress = "block_egress",
  RotateSecret = "rotate_secret",
  IsolateMemory = "isolate_memory",
  ReadOnlyMode = "read_only_mode",
  DisableMCP = "disable_mcp_server",
}

function buildContainmentPlan(signal: Signal): ContainmentAction[] {
  switch (signal.event) {
    case "secret_exfiltrated":
      return [
        ContainmentAction.StopRun,
        ContainmentAction.BlockEgress,
        ContainmentAction.RotateSecret,
        ContainmentAction.DisableTool,
      ];
    case "mcp_server_compromised":
      return [
        ContainmentAction.DisableMCP,
        ContainmentAction.BlockEgress,
        ContainmentAction.IsolateMemory,
      ];
    case "memory_poisoning_detected":
      return [ContainmentAction.StopRun, ContainmentAction.IsolateMemory];
    case "unsafe_tool_executed":
      return [
        ContainmentAction.StopRun,
        ContainmentAction.DisableTool,
        ContainmentAction.ReadOnlyMode,
      ];
    default:
      return [ContainmentAction.StopRun];
  }
}

/** Ordered IR path for containment / pivot (see §23 playbook). */
function autonomousContainmentSteps(): string[] {
  return [
    "stop_agent",
    "revoke_credentials",
    "block_egress",
    "save_tool_trace",
    "ignore_user_facing_summary",
    "pivot_check",
    "rotate_secrets",
    "notify_affected",
    "regression_eval",
  ];
}

function validateIncident(incident: Incident): void {
  if (!incident.id || !incident.title || !incident.owner) {
    throw new Error("incident has required empty fields");
  }

  if (!incident.severity || !incident.status) {
    throw new Error("incident has no severity or status");
  }

  if (incident.runIds.length === 0) {
    throw new Error("incident has no run ids");
  }

  if (!incident.detectedAt) {
    throw new Error("incident has no detected_at");
  }
}

function exportIncident(incident: Incident): string {
  validateIncident(incident);
  return JSON.stringify(incident, null, 2);
}
