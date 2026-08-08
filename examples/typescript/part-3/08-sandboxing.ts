// Illustrative examples for notes/part-3-processing-security/08-sandboxing.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).
/// <reference path="../types.d.ts" />

import { execFileSync } from "node:child_process";

interface CommandPolicy {
  allowedBinaries: Record<string, boolean>;
  timeout?: number;
  maxOutputBytes?: number;
  workDir?: string;
}

function runSandboxedCommand(
  policy: CommandPolicy,
  name: string,
  ...args: string[]
): string {
  if (!policy.allowedBinaries[name]) {
    throw new Error("binary is not allowed");
  }

  const timeoutMs = (policy.timeout && policy.timeout > 0 ? policy.timeout : 5) * 1000;
  const maxOutput = policy.maxOutputBytes && policy.maxOutputBytes > 0
    ? policy.maxOutputBytes
    : 64 * 1024;

  // Важно: execFileSync(name, args) без shell.
  // Не делать: execSync("sh -c ...user input...")
  const stdout = execFileSync(name, args, {
    cwd: policy.workDir,
    timeout: timeoutMs,
    maxBuffer: maxOutput,
    env: {
      PATH: "/usr/bin:/bin",
      LANG: "C",
    },
    encoding: "utf8",
  });

  return stdout;
}

// --- Sandbox policy для tool ---

interface SandboxPolicy {
  enabled: boolean;
  networkAllowed: boolean;
  allowedHosts?: string[];
  readOnly: boolean;
  maxInputBytes: number;
  maxOutputBytes: number;
  maxDurationSec: number;
  requiresApproval?: boolean;
}

interface ToolSpec {
  name: string;
  action: string;
  risk: string;
  sandboxPolicy: SandboxPolicy;
}

const TOOLS: Record<string, ToolSpec> = {
  read_docs: {
    name: "read_docs",
    action: "read",
    risk: "medium",
    sandboxPolicy: {
      enabled: true,
      networkAllowed: false,
      readOnly: true,
      maxInputBytes: 1 << 20,
      maxOutputBytes: 64 << 10,
      maxDurationSec: 5,
    },
  },
  run_code: {
    name: "run_code",
    action: "execute",
    risk: "high",
    sandboxPolicy: {
      enabled: true,
      networkAllowed: false,
      readOnly: false,
      maxInputBytes: 128 << 10,
      maxOutputBytes: 64 << 10,
      maxDurationSec: 3,
      requiresApproval: true,
    },
  },
};

/** EVAL-NETWORK-PREFLIGHT-01: env/network flags before start_agent. */
interface NetworkPreflightState {
  dnsPublic?: boolean;
  ipv4Public?: boolean;
  ipv6Public?: boolean;
  httpProxyPresent?: boolean;
  httpsProxyPresent?: boolean;
  allProxyPresent?: boolean;
  cloudMetadataReachable?: boolean;
  localhostPrivilegedServices?: boolean;
}

/** True → do not start agent. */
function failsNetworkPreflight(s: NetworkPreflightState): boolean {
  return Boolean(
    s.dnsPublic ||
      s.ipv4Public ||
      s.ipv6Public ||
      s.httpProxyPresent ||
      s.httpsProxyPresent ||
      s.allProxyPresent ||
      s.cloudMetadataReachable ||
      s.localhostPrivilegedServices,
  );
}

export { runSandboxedCommand, TOOLS, failsNetworkPreflight };

export type { CommandPolicy, SandboxPolicy, ToolSpec, NetworkPreflightState };
