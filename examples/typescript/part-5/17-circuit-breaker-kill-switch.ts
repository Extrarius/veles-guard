// Illustrative examples for notes/part-5-control-observability/17-circuit-breaker-kill-switch.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum State {
  Closed = "closed",
  Open = "open",
  HalfOpen = "half_open",
}

class CircuitBreaker {
  private state: State = State.Closed;
  private failures = 0;
  private openedAt = 0;
  private readonly threshold: number;
  private readonly cooldownMs: number;

  constructor(threshold: number, cooldownMs: number) {
    this.threshold = threshold;
    this.cooldownMs = cooldownMs;
  }

  allow(): boolean {
    switch (this.state) {
      case State.Closed:
        return true;
      case State.Open:
        if (Date.now() - this.openedAt >= this.cooldownMs) {
          this.state = State.HalfOpen;
          return true;
        }
        return false;
      case State.HalfOpen:
        return true;
      default:
        return false;
    }
  }

  success(): void {
    this.failures = 0;
    this.state = State.Closed;
  }

  failure(): void {
    this.failures += 1;
    if (this.failures >= this.threshold) {
      this.state = State.Open;
      this.openedAt = Date.now();
    }
  }
}

interface KillSwitch {
  enabled(scope: string): boolean;
}

class MemoryKillSwitch implements KillSwitch {
  private readonly closed = new Map<string, boolean>();

  activate(scope: string): void {
    this.closed.set(scope, true);
  }

  deactivate(scope: string): void {
    this.closed.set(scope, false);
  }

  enabled(scope: string): boolean {
    return this.closed.get(scope) ?? false;
  }
}

interface Tool {
  call(args: Record<string, unknown>): unknown;
}

class ErrToolDisabled extends Error {
  constructor() {
    super("tool disabled by kill-switch");
    this.name = "ErrToolDisabled";
  }
}

class ErrCircuitOpen extends Error {
  constructor() {
    super("tool circuit breaker is open");
    this.name = "ErrCircuitOpen";
  }
}

class SafeToolExecutor {
  toolName: string;
  tool: Tool;
  breaker: CircuitBreaker;
  kill: KillSwitch;

  constructor(toolName: string, tool: Tool, breaker: CircuitBreaker, kill: KillSwitch) {
    this.toolName = toolName;
    this.tool = tool;
    this.breaker = breaker;
    this.kill = kill;
  }

  call(args: Record<string, unknown>): unknown {
    let disabled: boolean;
    try {
      disabled = this.kill.enabled(`tool:${this.toolName}`);
    } catch (err) {
      // fail closed: если состояние kill-switch не удалось прочитать,
      // опаснее разрешить действие, чем заблокировать.
      throw err;
    }

    if (disabled) {
      throw new ErrToolDisabled();
    }

    if (!this.breaker.allow()) {
      throw new ErrCircuitOpen();
    }

    try {
      const result = this.tool.call(args);
      this.breaker.success();
      return result;
    } catch (err) {
      this.breaker.failure();
      throw err;
    }
  }
}

class RunBudget {
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
      throw new Error(`max steps exceeded: ${this.steps}`);
    }
    if (this.toolCalls > this.maxToolCalls) {
      throw new Error(`max tool calls exceeded: ${this.toolCalls}`);
    }
    if (this.denied > this.maxDenied) {
      throw new Error(`max denied actions exceeded: ${this.denied}`);
    }
  }
}

function agentLoop(budget: RunBudget, nextFn: () => void): void {
  while (true) {
    budget.steps += 1;
    budget.check();
    nextFn();
  }
}
