// Illustrative examples for notes/part-3-processing-security/10-secrets-management.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

interface SecretScope {
  toolName: string;
  action: string;
  userId: string;
  resource: string;
}

interface SecretProvider {
  getScopedToken(scope: SecretScope): Promise<string>;
}

interface HTTPClient {
  post(url: string, bearerToken: string, body: Uint8Array): Promise<Uint8Array>;
}

interface SendRequestArgs {
  endpoint: string;
  payload: string;
  // Важно: здесь нет Token/APIKey.
  // LLM не должна формировать секрет в аргументах.
}

class ExternalAPIClient {
  constructor(
    private secrets: SecretProvider,
    private http: HTTPClient,
  ) {}

  async sendRequest(userId: string, args: SendRequestArgs): Promise<Uint8Array> {
    if (!args.endpoint) {
      throw new Error("endpoint is required");
    }

    const token = await this.secrets.getScopedToken({
      toolName: "external_api.send_request",
      action: "send",
      userId,
      resource: args.endpoint,
    });

    return this.http.post(
      args.endpoint,
      token,
      new TextEncoder().encode(args.payload),
    );
  }
}

// --- Redacted logger ---

class Redactor {
  private patterns: RegExp[] = [
    /(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,]+/gi,
    /-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----/g,
    /bearer\s+[a-z0-9._\-]+/gi,
  ];

  redact(text: string): string {
    let out = text;
    for (const pattern of this.patterns) {
      out = out.replace(pattern, "[REDACTED_SECRET]");
    }
    return out;
  }
}

class SafeLogger {
  constructor(private redactor: Redactor) {}

  log(event: string, fields: Record<string, string>): void {
    const safe: Record<string, string> = {};
    for (const [key, value] of Object.entries(fields)) {
      if (looksSensitiveKey(key)) {
        safe[key] = "[REDACTED_SECRET]";
      } else {
        safe[key] = this.redactor.redact(value);
      }
    }

    // Здесь запись в реальный logger/tracing backend.
    void event;
    void safe;
  }
}

function looksSensitiveKey(key: string): boolean {
  const lower = key.toLowerCase();
  const markers = ["token", "password", "secret", "api_key", "authorization"];
  return markers.some((m) => lower.includes(m));
}

export { ExternalAPIClient, Redactor, SafeLogger, looksSensitiveKey };

export type { SecretScope, SecretProvider, HTTPClient, SendRequestArgs };
