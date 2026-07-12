// Illustrative examples for notes/part-2-input-security/05-rate-limiting-quotas-token-bombing.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

function estimateTokens(text: string): number {
  // Очень грубое приближение для конспекта:
  // 1 token ≈ 4 chars для английского.
  // Для русского и смешанного текста оценка может отличаться.
  const chars = [...text].length;
  if (chars === 0) {
    return 0;
  }
  return Math.floor(chars / 4) + 1;
}

interface RequestLimits {
  maxBytes: number;
  maxInputTokens: number;
  maxRequestsMin: number;
}

interface AdmissionDecision {
  allowed: boolean;
  reason: string;
}

function checkAdmission(input: string, limits: RequestLimits): AdmissionDecision {
  const bytes = new TextEncoder().encode(input).length;
  if (bytes > limits.maxBytes) {
    return {
      allowed: false,
      reason: `input too large: ${bytes} bytes`,
    };
  }

  const estimatedTokens = estimateTokens(input);
  if (estimatedTokens > limits.maxInputTokens) {
    return {
      allowed: false,
      reason: `input token budget exceeded: ${estimatedTokens} tokens`,
    };
  }

  return { allowed: true, reason: "" };
}

interface Bucket {
  count: number;
  resetTime: number;
}

class RateLimiter {
  private readonly limit: number;
  private readonly windowMs: number;
  private readonly buckets = new Map<string, Bucket>();

  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }

  allow(subject: string): boolean {
    const now = Date.now();
    let bucket = this.buckets.get(subject) ?? { count: 0, resetTime: 0 };

    if (now > bucket.resetTime) {
      bucket = { count: 0, resetTime: now + this.windowMs };
    }

    if (bucket.count >= this.limit) {
      this.buckets.set(subject, bucket);
      return false;
    }

    bucket.count += 1;
    this.buckets.set(subject, bucket);
    return true;
  }
}

class AgentBudget {
  maxSteps: number;
  maxToolCalls: number;
  maxTokens: number;
  steps = 0;
  toolCalls = 0;
  tokens = 0;

  constructor(maxSteps: number, maxToolCalls: number, maxTokens: number) {
    this.maxSteps = maxSteps;
    this.maxToolCalls = maxToolCalls;
    this.maxTokens = maxTokens;
  }

  addStep(): void {
    this.steps += 1;
    if (this.steps > this.maxSteps) {
      throw new Error(`agent step budget exceeded: ${this.steps}`);
    }
  }

  addToolCall(): void {
    this.toolCalls += 1;
    if (this.toolCalls > this.maxToolCalls) {
      throw new Error(`tool call budget exceeded: ${this.toolCalls}`);
    }
  }

  addTokens(n: number): void {
    this.tokens += n;
    if (this.tokens > this.maxTokens) {
      throw new Error(`token budget exceeded: ${this.tokens}`);
    }
  }
}

interface AgentStep {
  observation: string;
  usesTool: boolean;
}

interface StepRunner {
  next(): [AgentStep, boolean, Error | undefined];
}

function runWithBudget(runner: StepRunner, budget: AgentBudget): void {
  while (true) {
    budget.addStep();

    const [step, done, err] = runner.next();
    if (err) {
      throw err;
    }
    if (done) {
      return;
    }

    if (step.usesTool) {
      budget.addToolCall();
    }

    budget.addTokens(estimateTokens(step.observation));
  }
}
