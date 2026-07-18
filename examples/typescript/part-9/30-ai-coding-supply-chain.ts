// Illustrative examples for notes/part-9-ai-coding-security/30-ai-coding-supply-chain.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum ChangeKind {
  DependencyChange = "dependency_change",
  CIChange = "ci_change",
  DockerChange = "docker_change",
  InstructionChange = "instruction_change",
  MCPChange = "mcp_change",
  SkillChange = "skill_change",
  RegularCode = "regular_code",
}

function normalizePath(path: string): string {
  return path.replace(/\\/g, "/").replace(/\/+/g, "/").replace(/^\.\//, "");
}

function classifyChange(path: string): ChangeKind {
  const p = normalizePath(path);

  switch (p) {
    case "package.json":
    case "package-lock.json":
    case "pnpm-lock.yaml":
    case "yarn.lock":
    case "go.mod":
    case "go.sum":
    case "requirements.txt":
    case "poetry.lock":
      return ChangeKind.DependencyChange;
    case "Dockerfile":
      return ChangeKind.DockerChange;
    case "AGENTS.md":
    case "CLAUDE.md":
    case "GEMINI.md":
      return ChangeKind.InstructionChange;
  }

  if (p.startsWith(".github/workflows/")) {
    return ChangeKind.CIChange;
  }
  if (p.startsWith(".mcp/")) {
    return ChangeKind.MCPChange;
  }
  if (p.startsWith(".skills/")) {
    return ChangeKind.SkillChange;
  }

  return ChangeKind.RegularCode;
}

interface ChangedFile {
  path: string;
}

interface ReviewDecision {
  humanApproved?: boolean;
  securityApproved?: boolean;
  scannersPassed?: boolean;
  sbomUpdated?: boolean;
}

function blocksRelease(files: ChangedFile[], decision: ReviewDecision): boolean {
  let highRisk = false;

  for (const file of files) {
    const kind = classifyChange(file.path);
    if (
      kind === ChangeKind.DependencyChange ||
      kind === ChangeKind.CIChange ||
      kind === ChangeKind.DockerChange ||
      kind === ChangeKind.InstructionChange ||
      kind === ChangeKind.MCPChange ||
      kind === ChangeKind.SkillChange
    ) {
      highRisk = true;
    }
  }

  if (!decision.scannersPassed) {
    return true;
  }
  if (highRisk && !decision.securityApproved) {
    return true;
  }
  if (highRisk && !decision.humanApproved) {
    return true;
  }
  if (highRisk && !decision.sbomUpdated) {
    return true;
  }

  return false;
}

export {};
