// Illustrative examples for notes/part-9-ai-coding-security/29-ai-generated-code-review-spec-driven.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum Risk {
  Low = "Low",
  Medium = "Medium",
  High = "High",
  Critical = "Critical",
}

interface ChangedFile {
  path: string;
  additions?: number;
  deletions?: number;
}

function normalizePath(path: string): string {
  return path.replace(/\\/g, "/").replace(/\/+/g, "/").replace(/^\.\//, "");
}

function classifyFile(path: string): Risk {
  const p = normalizePath(path);

  if (p.startsWith(".github/workflows/")) {
    return Risk.Critical;
  }
  if (p === "Dockerfile" || p.endsWith(".Dockerfile")) {
    return Risk.High;
  }
  if (p === "package.json" || p === "package-lock.json" || p === "go.mod" || p === "go.sum") {
    return Risk.High;
  }
  if (p === "AGENTS.md" || p === "CLAUDE.md" || p.startsWith(".github/instructions/")) {
    return Risk.High;
  }
  if (p.includes("auth") || p.includes("permission") || p.includes("policy")) {
    return Risk.High;
  }
  if (p.endsWith("_test.go") || p.includes("/test")) {
    return Risk.Medium;
  }

  return Risk.Medium;
}

interface PullRequest {
  id: string;
  author: string;
  files: ChangedFile[];
  agentGenerated?: boolean;
  approvedByHuman?: boolean;
  securityApproved?: boolean;
  ciPassed?: boolean;
  securityScanPassed?: boolean;
}

function requiresSecurityReview(pr: PullRequest): boolean {
  if (pr.agentGenerated) {
    return true;
  }

  for (const file of pr.files) {
    const risk = classifyFile(file.path);
    if (risk === Risk.High || risk === Risk.Critical) {
      return true;
    }
  }

  return false;
}

function canMerge(pr: PullRequest): boolean {
  if (!pr.approvedByHuman) {
    return false;
  }
  if (!pr.ciPassed || !pr.securityScanPassed) {
    return false;
  }
  if (requiresSecurityReview(pr) && !pr.securityApproved) {
    return false;
  }
  return true;
}

export {};
