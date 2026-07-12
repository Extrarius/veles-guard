// Minimal type stubs for illustrative Node.js examples (no npm deps).

declare module "node:path" {
  export function isAbsolute(path: string): boolean;
  export function normalize(path: string): string;
  export function resolve(...paths: string[]): string;
  export const sep: string;
}

declare module "node:child_process" {
  export interface ExecFileSyncOptions {
    cwd?: string;
    timeout?: number;
    maxBuffer?: number;
    env?: Record<string, string | undefined>;
    encoding?: BufferEncoding;
  }

  export function execFileSync(
    file: string,
    args: readonly string[],
    options: ExecFileSyncOptions & { encoding: BufferEncoding },
  ): string;
}

declare module "node:crypto" {
  export interface Hash {
    update(data: string): Hash;
    digest(encoding: "hex"): string;
  }

  export function createHash(algorithm: "sha256"): Hash;
}
