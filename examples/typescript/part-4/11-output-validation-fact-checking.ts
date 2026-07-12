// Illustrative examples for notes/part-4-output-security/11-output-validation-fact-checking.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum OutputKind {
  FinalText = "final_text",
  StructuredJson = "structured_json",
  HTML = "html",
  Code = "code",
}

interface SourceRef {
  id: string;
  title: string;
  url: string;
}

interface Output {
  kind: OutputKind;
  text: string;
  meta: Record<string, string>;
  sources: SourceRef[];
}

interface ValidationResult {
  allowed: boolean;
  reason: string;
  risk: string; // High / Medium / Low
}

interface Validator {
  validate(out: Output): ValidationResult;
}

class Pipeline {
  validators: Validator[];

  constructor(validators: Validator[]) {
    this.validators = validators;
  }

  validate(out: Output): void {
    for (const validator of this.validators) {
      const result = validator.validate(out);
      if (!result.allowed) {
        throw new Error(`output blocked: ${result.reason} risk=${result.risk}`);
      }
    }
  }
}

class SecretLeakValidator implements Validator {
  validate(out: Output): ValidationResult {
    const text = out.text.toLowerCase();
    const markers = [
      "api_key",
      "authorization:",
      "bearer ",
      "password=",
      "secret=",
    ];
    for (const marker of markers) {
      if (text.includes(marker)) {
        return {
          allowed: false,
          reason: "possible secret leak",
          risk: "High",
        };
      }
    }
    return { allowed: true, reason: "", risk: "" };
  }
}

class HTMLPolicyValidator implements Validator {
  validate(out: Output): ValidationResult {
    if (out.kind !== OutputKind.HTML) {
      return { allowed: true, reason: "", risk: "" };
    }

    const lower = out.text.toLowerCase();
    const disallowed = [
      "<script",
      "javascript:",
      "onerror=",
      "onclick=",
      "<iframe",
    ];
    for (const token of disallowed) {
      if (lower.includes(token)) {
        return {
          allowed: false,
          reason: "unsafe html output",
          risk: "High",
        };
      }
    }
    return { allowed: true, reason: "", risk: "" };
  }
}

class SourceRequiredValidator implements Validator {
  validate(out: Output): ValidationResult {
    if (out.meta["requires_sources"] !== "true") {
      return { allowed: true, reason: "", risk: "" };
    }
    if (out.sources.length === 0) {
      return {
        allowed: false,
        reason: "answer requires sources but none provided",
        risk: "Medium",
      };
    }
    return { allowed: true, reason: "", risk: "" };
  }
}

function publish(pipeline: Pipeline, out: Output): void {
  if (!out.text) {
    throw new Error("empty output");
  }
  pipeline.validate(out);
}

interface CustomerMessage {
  subject: string;
  body: string;
  tone: string;
}

const ALLOWED_TONE: Record<string, boolean> = {
  neutral: true,
  formal: true,
  friendly: true,
};

const ALLOWED_FIELDS = new Set(["subject", "body", "tone"]);

function parseCustomerMessage(raw: string): CustomerMessage {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    throw new Error(`invalid structured output: ${String(err)}`);
  }

  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new Error("invalid structured output: expected object");
  }

  const record = data as Record<string, unknown>;
  const unknown = Object.keys(record).filter((key) => !ALLOWED_FIELDS.has(key));
  if (unknown.length > 0) {
    throw new Error(`invalid structured output: unknown fields ${unknown.join(", ")}`);
  }

  const subject = String(record.subject ?? "");
  const body = String(record.body ?? "");
  const tone = String(record.tone ?? "");

  if (!subject || !body) {
    throw new Error("subject and body are required");
  }

  if (!ALLOWED_TONE[tone]) {
    throw new Error(`unsupported tone: "${tone}"`);
  }

  if (body.toLowerCase().includes("password")) {
    throw new Error("message may contain sensitive data");
  }

  return { subject, body, tone };
}

interface SourceEvidenceStore {
  exists(sourceId: string): boolean;
  allowedForUser(userId: string, sourceId: string): boolean;
}

function validateSources(
  userId: string,
  sources: SourceRef[],
  store: SourceEvidenceStore,
): void {
  for (const source of sources) {
    if (!source.id) {
      throw new Error("source id is required");
    }
    if (!store.exists(source.id)) {
      throw new Error(`unknown source: ${source.id}`);
    }
    if (!store.allowedForUser(userId, source.id)) {
      throw new Error(`source is not allowed for user: ${source.id}`);
    }
  }
}
