// Illustrative examples for notes/part-9-ai-coding-security/28-coding-agent-permissions-sandbox-approval.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum Mode {
  ReadOnly = "read_only",
  WorkspaceWrite = "workspace_write",
  NetworkAllowed = "network_allowed",
  FullAccess = "danger_full_access",
}

enum ActionType {
  ReadFile = "read_file",
  WriteFile = "write_file",
  RunShell = "run_shell",
  NetworkCall = "network_call",
  InstallDep = "install_dependency",
  EditWorkflow = "edit_workflow",
  ReadSecret = "read_secret",
}

interface Action {
  type: ActionType;
  path?: string;
  command?: string;
  url?: string;
}

class Policy {
  mode: Mode;
  workspaceRoot: string;
  networkAllowlist: string[];

  constructor(mode: Mode, workspaceRoot: string, networkAllowlist: string[] = []) {
    this.mode = mode;
    this.workspaceRoot = workspaceRoot.replace(/\\/g, "/");
    this.networkAllowlist = networkAllowlist;
  }

  allow(action: Action): void {
    switch (action.type) {
      case ActionType.ReadFile:
        this.validatePath(action.path ?? "");
        return;
      case ActionType.WriteFile:
        if (
          this.mode !== Mode.WorkspaceWrite &&
          this.mode !== Mode.NetworkAllowed &&
          this.mode !== Mode.FullAccess
        ) {
          throw new Error("write denied in current mode");
        }
        this.validatePath(action.path ?? "");
        return;
      case ActionType.RunShell:
        if (this.mode === Mode.ReadOnly) {
          throw new Error("shell denied in read-only mode");
        }
        requiresApproval("shell command requires approval");
        return;
      case ActionType.NetworkCall:
        if (this.mode !== Mode.NetworkAllowed && this.mode !== Mode.FullAccess) {
          throw new Error("network denied in current mode");
        }
        this.validateUrl(action.url ?? "");
        return;
      case ActionType.InstallDep:
        requiresApproval("dependency install requires approval");
        return;
      case ActionType.EditWorkflow:
        throw new Error("CI workflow edit requires mandatory human review");
      case ActionType.ReadSecret:
        throw new Error("secret read is blocked");
      default:
        throw new Error("unknown action");
    }
  }

  validatePath(path: string): void {
    const root = this.workspaceRoot.replace(/\/+$/, "");
    const clean = path.replace(/\\/g, "/");
    const rel = clean.startsWith(root) ? clean.slice(root.length).replace(/^\//, "") : clean;
    if (rel.startsWith("..") || rel.startsWith("/")) {
      throw new Error("path escapes workspace");
    }
  }

  validateUrl(raw: string): void {
    const u = new URL(raw);
    if (u.protocol !== "https:") {
      throw new Error("only https is allowed");
    }
    const host = u.hostname.toLowerCase();
    for (const allowed of this.networkAllowlist) {
      if (host === allowed || host.endsWith("." + allowed)) {
        return;
      }
    }
    throw new Error("network destination denied");
  }
}

function requiresApproval(reason: string): void {
  throw new Error(`approval_required: ${reason}`);
}

const allowedCommands: Record<string, boolean> = {
  "go test ./...": true,
  "go vet ./...": true,
  "npm test": true,
  "npm run lint": true,
};

function validateCommand(cmd: string): void {
  const trimmed = cmd.trim();

  if (trimmed.includes("curl ") && trimmed.includes("| sh")) {
    throw new Error("curl pipe shell is forbidden");
  }

  if (trimmed.includes("rm -rf /")) {
    throw new Error("dangerous delete command");
  }

  if (!allowedCommands[trimmed]) {
    throw new Error("command is not allowlisted");
  }
}

type HookPhase = "pre" | "post";

/** Stub: hook allow without policy → deny; post cannot undo. */
function gateHook(phase: HookPhase, hookAllow: boolean, policyAllow: boolean): void {
  if (hookAllow && !policyAllow) {
    throw new Error("deny: hook allow is not policy");
  }
  if (phase === "post") {
    throw new Error("post hook cannot undo");
  }
  if (!policyAllow) {
    throw new Error("deny: policy");
  }
}

function modeRank(mode: string): number {
  const ranks: Record<string, number> = {
    read_only: 0,
    default: 0,
    workspace_write: 1,
    acceptEdits: 1,
    auto: 2,
    network: 2,
    bypass: 3,
    bypassPermissions: 3,
    danger_full_access: 3,
  };
  return ranks[mode] ?? 1;
}

/** Stub: child tools not ⊆ parent → deny; child mode wider → deny. */
function gateChild(
  parentTools: string[],
  childTools: string[],
  parentMode: string,
  childMode: string
): void {
  const allow = new Set(parentTools);
  for (const t of childTools) {
    if (!allow.has(t)) {
      throw new Error("deny: child tool not in parent set");
    }
  }
  if (modeRank(childMode) > modeRank(parentMode)) {
    throw new Error("deny: child mode wider than parent");
  }
}

export {};
