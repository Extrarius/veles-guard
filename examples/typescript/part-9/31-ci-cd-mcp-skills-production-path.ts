// Illustrative examples for notes/part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

function normalizePath(path: string): string {
  return path.replace(/\\/g, "/").replace(/\/+/g, "/").replace(/^\.\//, "");
}

function isProductionPath(path: string): boolean {
  const p = normalizePath(path);

  if (p.startsWith(".github/workflows/")) {
    return true;
  }
  if (p.startsWith("deploy/") || p.startsWith("k8s/") || p.startsWith("helm/")) {
    return true;
  }
  if (p === "Dockerfile" || p.endsWith(".Dockerfile")) {
    return true;
  }
  if (p.includes("terraform") || p.endsWith(".tf")) {
    return true;
  }
  if (p === "CODEOWNERS" || p.endsWith("/CODEOWNERS")) {
    return true;
  }

  return false;
}

interface PR {
  id: string;
  agentGenerated?: boolean;
  changedFiles?: string[];
  humanApproved?: boolean;
  securityApproved?: boolean;
  requiredChecksOK?: boolean;
}

function needsProductionReview(pr: PR): boolean {
  if (pr.agentGenerated) {
    return true;
  }
  for (const path of pr.changedFiles ?? []) {
    if (isProductionPath(path)) {
      return true;
    }
  }
  return false;
}

function canEnterProductionPath(pr: PR): boolean {
  if (!pr.requiredChecksOK) {
    return false;
  }
  if (needsProductionReview(pr) && !pr.humanApproved) {
    return false;
  }
  if (needsProductionReview(pr) && !pr.securityApproved) {
    return false;
  }
  return true;
}

export {};
