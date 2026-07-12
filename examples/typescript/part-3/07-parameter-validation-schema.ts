// Illustrative examples for notes/part-3-processing-security/07-parameter-validation-schema.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).
/// <reference path="../types.d.ts" />

import { isAbsolute, normalize, resolve, sep } from "node:path";

const ALLOWED_HOSTS = new Set(["api.example.com", "docs.example.com"]);

// --- JSON schema через строгий decoder ---

interface FetchURLArgs {
  url: string;
  timeoutSeconds: number;
}

function decodeStrict(raw: string): Record<string, unknown> {
  const obj = JSON.parse(raw);
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
    throw new Error("expected a JSON object");
  }
  return obj as Record<string, unknown>;
}

function validateFetchURLArgs(obj: Record<string, unknown>): FetchURLArgs {
  const allowed = new Set(["url", "timeout_seconds"]);
  const extra = Object.keys(obj).filter((k) => !allowed.has(k));
  if (extra.length > 0) {
    throw new Error(`unknown fields: ${extra.join(", ")}`);
  }

  const url = typeof obj.url === "string" ? obj.url : "";
  if (!url) {
    throw new Error("url is required");
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("invalid url");
  }
  if (parsed.protocol !== "https:") {
    throw new Error("only https scheme is allowed");
  }
  if (!ALLOWED_HOSTS.has(parsed.hostname.toLowerCase())) {
    throw new Error(`host is not allowed: ${parsed.hostname}`);
  }

  const timeout = obj.timeout_seconds;
  if (
    typeof timeout !== "number" ||
    !Number.isInteger(timeout) ||
    timeout <= 0 ||
    timeout > 10
  ) {
    throw new Error("timeout must be between 1 and 10 seconds");
  }

  return { url, timeoutSeconds: timeout };
}

// --- Безопасная проверка пути ---

function safeJoin(baseDir: string, userPath: string): string {
  if (!userPath) {
    throw new Error("path is required");
  }

  const clean = normalize(userPath);
  if (isAbsolute(clean)) {
    throw new Error("absolute paths are not allowed");
  }

  const baseAbs = resolve(baseDir);
  const fullAbs = resolve(baseAbs, clean);

  if (fullAbs !== baseAbs && !fullAbs.startsWith(baseAbs + sep)) {
    throw new Error("path escapes base directory");
  }

  return fullAbs;
}

// --- Ownership check ---

interface ResourceAccessChecker {
  canAccessCustomer(userId: string, customerId: string): boolean;
}

function validateReadCustomer(
  userId: string,
  customerId: string,
  access: ResourceAccessChecker,
): void {
  if (!customerId) {
    throw new Error("customer_id is required");
  }
  if (!access.canAccessCustomer(userId, customerId)) {
    throw new Error("customer does not belong to user");
  }
}

export {
  decodeStrict,
  validateFetchURLArgs,
  safeJoin,
  validateReadCustomer,
};

export type { FetchURLArgs, ResourceAccessChecker };
