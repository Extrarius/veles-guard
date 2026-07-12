// Illustrative examples for notes/part-5-control-observability/15-observability-tracing.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).
/// <reference path="../types.d.ts" />

import { createHash } from "node:crypto";

enum Severity {
  Info = "INFO",
  Warn = "WARN",
  Error = "ERROR",
}

interface AuditEvent {
  time?: Date;
  runId: string;
  event: string;
  severity: Severity;
  component: string;
  tool?: string;
  risk?: string;
  decision?: string;
  reason?: string;
  attrs?: Record<string, unknown>;
}

const SECRET_PATTERNS = [
  /(api[_-]?key|token|secret|password)\s*[:=]\s*['"]?[^'"\s]+/i,
  /bearer\s+[a-z0-9._\-]+/i,
];

function redact(value: string): string {
  let out = value;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, "[REDACTED]");
  }
  return out;
}

function hashValue(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

class Logger {
  emit(event: AuditEvent): void {
    const time = event.time ?? new Date();
    const attrs = event.attrs ? { ...event.attrs } : undefined;

    if (attrs) {
      for (const [key, value] of Object.entries(attrs)) {
        if (typeof value === "string") {
          attrs[key] = redact(value);
        }
      }
    }

    const payload = {
      time: time.toISOString(),
      run_id: event.runId,
      event: event.event,
      severity: event.severity,
      component: event.component,
      tool: event.tool,
      risk: event.risk,
      decision: event.decision,
      reason: event.reason,
      attrs,
    };

    console.log(JSON.stringify(payload));
  }
}

function logPolicyDecision(
  logger: Logger,
  runId: string,
  tool: string,
  decision: string,
  reason: string,
  risk: string,
  args: Record<string, unknown>,
): void {
  const argsJson = JSON.stringify(args);

  logger.emit({
    runId,
    event: "policy_decision",
    severity: Severity.Info,
    component: "policy",
    tool,
    risk,
    decision,
    reason,
    attrs: {
      args_hash: hashValue(argsJson),
    },
  });
}

function logEgressBlocked(
  logger: Logger,
  runId: string,
  url: string,
  reason: string,
): void {
  logger.emit({
    runId,
    event: "egress_blocked",
    severity: Severity.Warn,
    component: "egress",
    reason,
    attrs: {
      url: redact(url),
    },
  });
}
