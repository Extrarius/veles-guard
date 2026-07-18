// Illustrative examples for notes/part-10-course-appendix/33-course-appendix-agentic-security.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

const allowed = new Set<string>(["read_file", "repo_search"]);

/** Deny by default: tool must be in the allowlist. */
function authorize(tool: string): void {
  if (!allowed.has(tool)) {
    throw new Error(`tool "${tool}" not in allowlist`);
  }
}

export { authorize, allowed };
