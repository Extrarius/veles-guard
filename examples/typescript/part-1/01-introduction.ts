// Illustrative examples for notes/part-1-architecture-threats/01-introduction.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

interface ToolCall {
  name: string;
  args: Record<string, unknown>;
}

interface Step {
  finalAnswer: string;
  toolCall?: ToolCall;
}

interface LLMClient {
  plan(task: string): Step;
  summarize(task: string, observation: string): string;
}

interface Tool {
  call(args: Record<string, unknown>): string;
}

interface Policy {
  allowToolCall(call: ToolCall): void;
}

interface AuditLogger {
  toolCallRequested(call: ToolCall): void;
  toolCallDenied(call: ToolCall, reason: Error): void;
  toolCallExecuted(call: ToolCall, observation: string): void;
}

class Agent {
  constructor(
    private llm: LLMClient,
    private tools: Map<string, Tool>,
    private policy: Policy,
    private log: AuditLogger,
  ) {}

  run(task: string): string {
    // Риск: prompt injection может быть уже внутри task.
    // Поэтому task нельзя считать доверенной управляющей инструкцией.
    const step = this.llm.plan(task);

    if (!step.toolCall) {
      // Риск: output может содержать секреты или галлюцинации.
      // В реальной системе здесь нужен output validation / redaction.
      return step.finalAnswer;
    }

    const call = step.toolCall;

    const tool = this.tools.get(call.name);
    if (!tool) {
      throw new Error(`unknown tool: ${call.name}`);
    }

    // Риск: tool hijacking / tool misuse.
    // Модель не должна вызывать инструмент напрямую.
    // Сначала проверяем права, scope, параметры и необходимость approval.
    this.log.toolCallRequested(call);
    try {
      this.policy.allowToolCall(call);
    } catch (err) {
      const reason = err instanceof Error ? err : new Error(String(err));
      this.log.toolCallDenied(call, reason);
      throw new Error(`tool call denied: ${reason.message}`);
    }

    const observation = tool.call(call.args);

    if (!observation) {
      throw new Error("empty tool observation");
    }

    this.log.toolCallExecuted(call, observation);

    // Риск: tool output может быть poisoned.
    // Нельзя слепо превращать observation в новые инструкции.
    return this.llm.summarize(task, observation);
  }
}

export { Agent };

export type { ToolCall, Step, LLMClient, Tool, Policy, AuditLogger };
