// Illustrative examples for notes/part-4-output-security/13-egress-control-data-exfiltration.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum DataClass {
  Public = "public",
  Internal = "internal",
  Confidential = "confidential",
  Secret = "secret",
  Personal = "personal",
}

enum EgressChannel {
  HTTP = "http",
  Email = "email",
  Browser = "browser",
  Log = "log",
  AgentMessage = "agent_message",
}

/** Канон «что можно отдать модели» (§04 #ai-data-classes-d0-d4). Не путать с DataClass egress. */
enum AIDataClass {
  D0Public = "d0_public",
  D1Internal = "d1_internal",
  D2ConfidentialNDA = "d2_confidential_nda",
  D3Regulated = "d3_regulated",
  D4Secrets = "d4_secrets",
}

enum InferenceRoute {
  Internal = "internal",
  External = "external",
  Specialized = "specialized",
  Reject = "reject",
}

/** Учебная политика AI Gateway по канону D0–D4 (§04). */
function routeInference(dc: AIDataClass): InferenceRoute {
  if (dc === AIDataClass.D4Secrets) {
    throw new Error("D4 secrets must not reach any model");
  }
  if (
    dc === AIDataClass.D3Regulated ||
    dc === AIDataClass.D2ConfidentialNDA ||
    dc === AIDataClass.D1Internal
  ) {
    return InferenceRoute.Internal;
  }
  if (dc === AIDataClass.D0Public) {
    return InferenceRoute.External;
  }
  throw new Error("unknown AI data class");
}

export { routeInference, InferenceRoute, AIDataClass };

interface EgressRequest {
  userId: string;
  tenantId: string;
  channel: EgressChannel;
  destination: string;
  payload: string;
  dataClasses: DataClass[];
  purpose: string;
}

interface EgressDecision {
  allowed: boolean;
  needsApproval: boolean;
  reason: string;
  sanitizedBody: string;
}

class EgressPolicy {
  allowedHttpDomains: Record<string, boolean>;
  allowedEmailDomains: Record<string, boolean>;

  constructor(
    allowedHttpDomains: Record<string, boolean> = {},
    allowedEmailDomains: Record<string, boolean> = {},
  ) {
    this.allowedHttpDomains = allowedHttpDomains;
    this.allowedEmailDomains = allowedEmailDomains;
  }

  decide(req: EgressRequest): EgressDecision {
    if (!req.destination) {
      throw new Error("destination is required");
    }

    if (contains(req.dataClasses, DataClass.Secret)) {
      return {
        allowed: false,
        needsApproval: false,
        reason: "secret data cannot leave runtime",
        sanitizedBody: "",
      };
    }

    if (
      contains(req.dataClasses, DataClass.Personal) ||
      contains(req.dataClasses, DataClass.Confidential)
    ) {
      return {
        allowed: false,
        needsApproval: true,
        reason: "personal/confidential data requires approval",
        sanitizedBody: "",
      };
    }

    switch (req.channel) {
      case EgressChannel.HTTP:
      case EgressChannel.Browser:
        if (!this.allowedURL(req.destination)) {
          return {
            allowed: false,
            needsApproval: false,
            reason: "destination domain is not allowed",
            sanitizedBody: "",
          };
        }
        break;
      case EgressChannel.Email:
        if (!this.allowedEmail(req.destination)) {
          return {
            allowed: false,
            needsApproval: false,
            reason: "recipient domain is not allowed",
            sanitizedBody: "",
          };
        }
        break;
      case EgressChannel.Log:
        // Logs are internal, but still need redaction.
        break;
      default:
        return {
          allowed: false,
          needsApproval: false,
          reason: "unsupported egress channel",
          sanitizedBody: "",
        };
    }

    return {
      allowed: true,
      needsApproval: false,
      reason: "",
      sanitizedBody: redact(req.payload),
    };
  }

  allowedURL(raw: string): boolean {
    let parsed: URL;
    try {
      parsed = new URL(raw);
    } catch {
      return false;
    }
    if (!parsed.protocol || !parsed.hostname) {
      return false;
    }
    if (parsed.protocol !== "https:") {
      return false;
    }
    return Boolean(this.allowedHttpDomains[parsed.hostname.toLowerCase()]);
  }

  allowedEmail(addr: string): boolean {
    const parts = addr.split("@");
    if (parts.length !== 2) {
      return false;
    }
    const domain = parts[1].toLowerCase();
    return Boolean(this.allowedEmailDomains[domain]);
  }
}

function contains(classes: DataClass[], target: DataClass): boolean {
  return classes.includes(target);
}

function redact(value: string): string {
  const markers = ["api_key=", "password=", "token=", "secret="];
  let out = value;
  let lower = out.toLowerCase();
  for (const marker of markers) {
    const idx = lower.indexOf(marker);
    if (idx >= 0) {
      out = out.slice(0, idx) + marker + "[REDACTED]";
      lower = out.toLowerCase();
    }
  }
  return out;
}

enum Taint {
  None = "none",
  UserInput = "user_input",
  SecretSource = "secret_source",
  PersonalData = "personal_data",
  TenantData = "tenant_data",
}

class AgentValue {
  value: string;
  taints: Taint[];

  constructor(value: string, taints: Taint[] = []) {
    this.value = value;
    this.taints = taints;
  }

  hasTaint(taint: Taint): boolean {
    return this.taints.includes(taint);
  }
}

function buildEgressFromValue(
  userId: string,
  tenantId: string,
  dest: string,
  val: AgentValue,
): EgressRequest {
  const classes: DataClass[] = [DataClass.Internal];

  if (val.hasTaint(Taint.SecretSource)) {
    classes.push(DataClass.Secret);
  }
  if (val.hasTaint(Taint.PersonalData)) {
    classes.push(DataClass.Personal);
  }
  if (val.hasTaint(Taint.TenantData)) {
    classes.push(DataClass.Confidential);
  }

  return {
    userId,
    tenantId,
    channel: EgressChannel.HTTP,
    destination: dest,
    payload: val.value,
    dataClasses: classes,
    purpose: "agent_outbound_request",
  };
}

class SafeHTTPClient {
  policy: EgressPolicy;

  constructor(policy: EgressPolicy) {
    this.policy = policy;
  }

  async post(req: EgressRequest): Promise<Response> {
    const decision = this.policy.decide(req);
    if (decision.needsApproval) {
      throw new Error(`egress requires approval: ${decision.reason}`);
    }
    if (!decision.allowed) {
      throw new Error(`egress blocked: ${decision.reason}`);
    }

    return fetch(req.destination, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: decision.sanitizedBody,
    });
  }
}
