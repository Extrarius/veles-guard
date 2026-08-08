// Illustrative examples for notes/part-5-control-observability/16-monitoring-alerting.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum Severity {
  Low = "Low",
  Medium = "Medium",
  High = "High",
  Critical = "Critical",
}

interface SecuritySignal {
  time?: Date;
  runId: string;
  userHash: string;
  event: string;
  tool: string;
  severity: Severity;
  reason: string;
  attrs: Record<string, string>;
}

class CounterStore {
  private readonly counts = new Map<string, number>();

  inc(key: string): void {
    this.counts.set(key, (this.counts.get(key) ?? 0) + 1);
  }

  get(key: string): number {
    return this.counts.get(key) ?? 0;
  }
}

interface Alert {
  name: string;
  severity: Severity;
  message: string;
  runId: string;
}

interface AlertSink {
  send(alert: Alert): void;
}

class Rule {
  name: string;
  event: string;
  threshold: number;
  severity: Severity;

  constructor(name: string, event: string, threshold: number, severity: Severity) {
    this.name = name;
    this.event = event;
    this.threshold = threshold;
    this.severity = severity;
  }

  evaluate(signal: SecuritySignal, store: CounterStore): Alert | undefined {
    if (signal.event !== this.event) {
      return undefined;
    }

    const key = `${this.event}:${signal.userHash}:${signal.tool}`;
    store.inc(key);

    if (store.get(key) < this.threshold) {
      return undefined;
    }

    return {
      name: this.name,
      severity: this.severity,
      message: `threshold reached for event=${signal.event} tool=${signal.tool}`,
      runId: signal.runId,
    };
  }
}

class Monitor {
  store: CounterStore;
  rules: Rule[];
  sink: AlertSink;

  constructor(store: CounterStore, rules: Rule[], sink: AlertSink) {
    this.store = store;
    this.rules = rules;
    this.sink = sink;
  }

  handle(signal: SecuritySignal): void {
    if (!signal.time) {
      signal.time = new Date();
    }

    for (const rule of this.rules) {
      const alert = rule.evaluate(signal, this.store);
      if (!alert) {
        continue;
      }
      this.sink.send(alert);
    }
  }
}

const RULES: Rule[] = [
  new Rule("Prompt injection spike", "prompt_injection_detected", 5, Severity.High),
  new Rule("Repeated denied tool calls", "tool_denied", 3, Severity.Medium),
  new Rule("Blocked egress attempts", "egress_blocked", 1, Severity.High),
  new Rule("Budget runaway", "budget_exceeded", 1, Severity.High),
];

/** Weak signals for one run (scope drift / monitoring tampering). */
interface WeakSignals {
  newExternalDomain?: boolean;
  credentialSearch?: boolean;
  monitoringTampering?: boolean;
  outOfScopeAction?: boolean;
  continueAfterDeny?: boolean;
  realSecretAccess?: boolean;
}

/**
 * True on emergency-stop hard trigger. Stop via §17.
 * Correlation (new domain + credential search + tampering + out-of-scope)
 * is covered by these flags; credentialSearch alone does not stop.
 */
function shouldAutoStop(s: WeakSignals): boolean {
  return Boolean(
    s.monitoringTampering ||
      s.continueAfterDeny ||
      s.realSecretAccess ||
      s.newExternalDomain ||
      s.outOfScopeAction,
  );
}

export { shouldAutoStop, type WeakSignals };
