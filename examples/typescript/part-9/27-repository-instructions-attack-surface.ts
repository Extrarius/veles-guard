// Illustrative examples for notes/part-9-ai-coding-security/27-repository-instructions-attack-surface.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum Trust {
  TrustedInstruction = "trusted_instruction",
  UntrustedContext = "untrusted_context",
  HighRiskConfig = "high_risk_config",
}

const forbiddenInstructionMarkers = [
  "ignore security policy",
  "disable approval",
  "turn off sandbox",
  "run with full access",
  "print secrets",
  "bypass egress",
  "disable tests",
  "remove security check",
];

function normalizePath(path: string): string {
  return path.replace(/\\/g, "/").replace(/\/+/g, "/").replace(/^\.\//, "");
}

function classifyPath(path: string): Trust {
  const clean = normalizePath(path);

  if (clean === "AGENTS.md" || clean.endsWith("/AGENTS.md")) {
    return Trust.TrustedInstruction;
  }
  if (clean === "CLAUDE.md" || clean === "GEMINI.md") {
    return Trust.TrustedInstruction;
  }
  if (clean === ".github/copilot-instructions.md") {
    return Trust.TrustedInstruction;
  }
  if (clean.startsWith(".github/instructions/") && clean.endsWith(".instructions.md")) {
    return Trust.TrustedInstruction;
  }
  if (clean.startsWith(".github/workflows/")) {
    return Trust.HighRiskConfig;
  }
  if (
    clean === "go.mod" ||
    clean === "go.sum" ||
    clean === "package.json" ||
    clean.endsWith("lock")
  ) {
    return Trust.HighRiskConfig;
  }

  return Trust.UntrustedContext;
}

function validateInstructionText(text: string): void {
  const lower = text.toLowerCase();
  for (const marker of forbiddenInstructionMarkers) {
    if (lower.includes(marker)) {
      throw new Error(`instruction attempts to override security policy: ${marker}`);
    }
  }
}

export {};
