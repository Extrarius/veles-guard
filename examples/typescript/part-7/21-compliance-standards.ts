// Illustrative examples for notes/part-7-testing-compliance/21-compliance-standards.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum Status {
  Implemented = "implemented",
  Partial = "partial",
  Planned = "planned",
  AcceptedRisk = "accepted_risk",
}

interface Control {
  id: string;
  framework: string;
  requirement: string;
  control: string;
  implementation: string;
  evidence: string[];
  owner: string;
  status: Status;
  reviewDate?: Date;
}

const CONTROLS: Control[] = [
  {
    id: "CTRL-001",
    framework: "OWASP LLM01",
    requirement: "Prompt Injection mitigation",
    control: "Detect and isolate untrusted instructions",
    implementation: "Input guard + context isolation + tool approval",
    evidence: ["RT-001", "prompt_injection_detected logs"],
    owner: "agent-runtime",
    status: Status.Implemented,
  },
  {
    id: "CTRL-002",
    framework: "OWASP LLM02",
    requirement: "Sensitive information disclosure prevention",
    control: "PII/secrets redaction before output and logs",
    implementation: "Redaction pipeline + egress scanner",
    evidence: ["redaction logs", "egress_blocked events"],
    owner: "security",
    status: Status.Partial,
  },
  {
    id: "CTRL-003",
    framework: "NIST AI RMF Measure",
    requirement: "Testing, evaluation, verification and validation",
    control: "Adversarial regression suite",
    implementation: "Red team cases in CI",
    evidence: ["redteam-report.md", "CI run artifacts"],
    owner: "platform",
    status: Status.Planned,
  },
];

function validateControls(controls: Control[]): void {
  for (const item of controls) {
    if (!item.id || !item.framework || !item.control) {
      throw new Error("control has required empty fields");
    }

    if (!item.owner) {
      throw new Error(`control has no owner: ${item.id}`);
    }

    if (item.status === Status.Implemented && item.evidence.length === 0) {
      throw new Error(`implemented control has no evidence: ${item.id}`);
    }

    if (item.status === Status.AcceptedRisk && !item.reviewDate) {
      throw new Error(`accepted risk has no review date: ${item.id}`);
    }
  }
}

function exportJSON(controls: Control[]): string {
  validateControls(controls);
  return JSON.stringify(controls, null, 2);
}
