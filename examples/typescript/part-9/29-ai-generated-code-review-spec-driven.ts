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

/** PR/issue as untrusted input (#pr-issue-untrusted-input). */
interface PRReviewInput {
  title?: string;
  body?: string;
  comments?: string;
}

/** Explicit data frame; content is not policy/instructions. */
function wrapUntrusted(label: string, text: string): string {
  return `BEGIN_UNTRUSTED_DATA label="${label}"\n${text}\nEND_UNTRUSTED_DATA\n`;
}

/** Heuristic hits only — not the §03 detector pipeline. */
function scanPRText(s: string): string[] {
  const lower = s.toLowerCase();
  const hits: string[] = [];
  for (const p of [
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "system prompt",
    "you are now",
    "do not follow",
  ]) {
    if (lower.includes(p)) {
      hits.push(`instruction_override:${p}`);
    }
  }
  if (/[\u200b\u200c\u200d\ufeff]/.test(s)) {
    hits.push("hidden_or_format_char");
  }
  return hits;
}

function prepareReviewContext(inp: PRReviewInput): { framed: string; hits: string[] } {
  const raw = [inp.title, inp.body, inp.comments].filter(Boolean).join("\n").trim();
  const hits = scanPRText(raw);
  return { framed: wrapUntrusted("pr_or_issue", raw), hits };
}

export {
  Risk,
  classifyFile,
  requiresSecurityReview,
  canMerge,
  wrapUntrusted,
  scanPRText,
  prepareReviewContext,
};

export type { ChangedFile, PullRequest, PRReviewInput };
