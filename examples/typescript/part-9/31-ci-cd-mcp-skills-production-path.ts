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

type SkillLevel = "prototype" | "startup" | "production" | "regulated";

/** Minimum control names for a Skill Security level (illustrative). */
function requiredControls(level: SkillLevel): string[] {
  switch (level) {
    case "prototype":
      return ["attack_surface_awareness"];
    case "startup":
      return [
        "trusted_source",
        "manifest_review",
        "no_secrets_in_skill",
        "approval_dangerous",
      ];
    case "production":
      return [
        "trusted_source",
        "manifest_review",
        "no_secrets_in_skill",
        "approval_dangerous",
        "sandbox_scripts",
        "audit_log",
        "version_pin",
        "egress_control",
        "update_diff_review",
      ];
    case "regulated":
      return [
        "trusted_source",
        "manifest_review",
        "no_secrets_in_skill",
        "approval_dangerous",
        "sandbox_scripts",
        "audit_log",
        "version_pin",
        "egress_control",
        "update_diff_review",
        "formal_policy",
        "skill_allowlist",
        "threat_model",
        "mandatory_hitl",
      ];
  }
}

function meetsMinimum(
  level: SkillLevel,
  enabled: Record<string, boolean>,
): boolean {
  return requiredControls(level).every((c) => enabled[c] === true);
}

export {
  isProductionPath,
  needsProductionReview,
  canEnterProductionPath,
  requiredControls,
  meetsMinimum,
};
export type { PR, SkillLevel };
