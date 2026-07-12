// Illustrative examples for notes/part-2-input-security/04-pii-redaction-content-filtering.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum EntityType {
  Email = "EMAIL",
  Phone = "PHONE",
  Secret = "SECRET",
}

interface Entity {
  type: EntityType;
  start: number;
  end: number;
  value: string;
}

interface Recognizer {
  type: EntityType;
  pattern: RegExp;
}

const RECOGNIZERS: Recognizer[] = [
  {
    type: EntityType.Email,
    pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/,
  },
  {
    type: EntityType.Phone,
    pattern: /(\+?\d[\d\s\-()]{8,}\d)/i,
  },
  {
    type: EntityType.Secret,
    pattern: /(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s]+/i,
  },
];

function detectEntities(input: string): Entity[] {
  const entities: Entity[] = [];

  for (const recognizer of RECOGNIZERS) {
    const pattern = new RegExp(
      recognizer.pattern.source,
      recognizer.pattern.flags.includes("g")
        ? recognizer.pattern.flags
        : recognizer.pattern.flags + "g",
    );
    for (const match of input.matchAll(pattern)) {
      if (match.index === undefined) {
        continue;
      }
      entities.push({
        type: recognizer.type,
        start: match.index,
        end: match.index + match[0].length,
        value: match[0],
      });
    }
  }

  return entities;
}

function redact(input: string, entities: Entity[]): string {
  if (entities.length === 0) {
    return input;
  }

  // Простой вариант для конспекта: заменяем найденные значения.
  // В production лучше учитывать пересечения span'ов и сортировку по offset.
  let output = input;
  for (const entity of entities) {
    let replacement = `[${entity.type}]`;
    if (entity.type === EntityType.Secret) {
      replacement = "[SECRET_REDACTED]";
    }
    output = output.replace(entity.value, replacement);
  }
  return output;
}

enum InputAction {
  Allow = "allow",
  Mask = "mask",
  Block = "block",
}

interface RedactionDecision {
  action: InputAction;
  reason: string;
  entities: Entity[];
}

function decideRedaction(input: string): RedactionDecision {
  const entities = detectEntities(input);

  for (const entity of entities) {
    if (entity.type === EntityType.Secret) {
      return {
        action: InputAction.Block,
        reason: "secret detected in input",
        entities,
      };
    }
  }

  if (entities.length > 0) {
    return {
      action: InputAction.Mask,
      reason: "PII detected; input should be masked before LLM/logs",
      entities,
    };
  }

  return { action: InputAction.Allow, reason: "", entities: [] };
}

interface SanitizedInput {
  originalAllowed: boolean;
  text: string;
  redacted: boolean;
  reason: string;
}

// Minimal local injection guard (full detector: 03-prompt-injection-detection.*).
const INJECTION_GUARD =
  /ignore (all )?(previous|prior|system|developer) instructions|(reveal|print|show|dump).*(system prompt|developer message|hidden instruction)|(call|invoke|use).*(shell|exec|http|browser|email|delete|payment)|(send|upload|exfiltrate).*(secret|token|api key|password|env)/i;

function injectionBlocked(input: string): { allowed: boolean; reason: string } {
  if (INJECTION_GUARD.test(input.trim())) {
    return { allowed: false, reason: "high-risk prompt injection signal detected" };
  }
  return { allowed: true, reason: "" };
}

function sanitizeForLLM(input: string): SanitizedInput {
  const injection = injectionBlocked(input);
  if (!injection.allowed) {
    throw new Error(`prompt injection blocked: ${injection.reason}`);
  }

  const decision = decideRedaction(input);

  switch (decision.action) {
    case InputAction.Block:
      throw new Error(`input blocked: ${decision.reason}`);
    case InputAction.Mask:
      return {
        originalAllowed: false,
        text: redact(input, decision.entities),
        redacted: true,
        reason: decision.reason,
      };
    default:
      return { originalAllowed: true, text: input, redacted: false, reason: "" };
  }
}
