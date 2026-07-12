// Illustrative examples for notes/part-1-architecture-threats/02-threat-model.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum Severity {
  High = "High",
  Medium = "Medium",
  Low = "Low",
}

enum STRIDE {
  Spoofing = "Spoofing",
  Tampering = "Tampering",
  Repudiation = "Repudiation",
  InformationDisclosure = "Information Disclosure",
  DenialOfService = "Denial of Service",
  ElevationOfPrivilege = "Elevation of Privilege",
}

enum Status {
  Open = "open",
  Mitigated = "mitigated",
  Accepted = "accepted",
  NeedsOwner = "needs-owner",
}

interface Risk {
  id: string;
  dfdElement: string;
  layer: string;
  stride: STRIDE;
  scenario: string;
  severity: Severity;
  controls: string[];
  sections: string[];
  status: Status;
}

const AGENT_RISKS: Risk[] = [
  {
    id: "R-001",
    dfdElement: "User Input",
    layer: "input",
    stride: STRIDE.Tampering,
    scenario:
      "User prompt attempts to override system instructions or change the agent goal.",
    severity: Severity.High,
    controls: [
      "prompt injection detection",
      "context isolation",
      "intent validation",
    ],
    sections: ["03", "14"],
    status: Status.Open,
  },
  {
    id: "R-002",
    dfdElement: "Uploaded Docs / Web / Email",
    layer: "input",
    stride: STRIDE.Tampering,
    scenario:
      "Indirect prompt injection hidden in retrieved content influences tool selection.",
    severity: Severity.High,
    controls: [
      "treat retrieved content as data",
      "content sanitization",
      "tool approval",
    ],
    sections: ["03", "09"],
    status: Status.Open,
  },
  {
    id: "R-003",
    dfdElement: "Tool Router",
    layer: "processing",
    stride: STRIDE.ElevationOfPrivilege,
    scenario: "Agent calls a privileged tool outside its allowed role or scope.",
    severity: Severity.High,
    controls: ["RBAC", "tool allowlist", "schema validation", "human approval"],
    sections: ["06", "07", "14"],
    status: Status.Open,
  },
  {
    id: "R-004",
    dfdElement: "Memory / Vector Store",
    layer: "processing",
    stride: STRIDE.Tampering,
    scenario:
      "Malicious instruction is stored in memory and reused in future sessions.",
    severity: Severity.High,
    controls: [
      "memory isolation",
      "memory write policy",
      "context sanitization",
    ],
    sections: ["09"],
    status: Status.Open,
  },
  {
    id: "R-005",
    dfdElement: "Output Validator",
    layer: "output",
    stride: STRIDE.InformationDisclosure,
    scenario:
      "Final answer exposes secrets, internal prompts, credentials, or private context.",
    severity: Severity.High,
    controls: ["output validation", "secret scanning", "PII redaction"],
    sections: ["04", "11", "13"],
    status: Status.Open,
  },
  {
    id: "R-006",
    dfdElement: "Agent Loop",
    layer: "infrastructure",
    stride: STRIDE.DenialOfService,
    scenario:
      "Agent repeatedly calls expensive tools or LLM API until quota or budget is exhausted.",
    severity: Severity.Medium,
    controls: ["max steps", "timeouts", "quotas", "circuit breaker"],
    sections: ["05", "16", "17"],
    status: Status.Open,
  },
];

// --- Минимальная проверка риск-реестра ---

function highRisksWithoutControls(risks: Risk[]): Risk[] {
  return risks.filter(
    (risk) => risk.severity === Severity.High && risk.controls.length === 0,
  );
}

export { Severity, STRIDE, Status, AGENT_RISKS, highRisksWithoutControls };

export type { Risk };
