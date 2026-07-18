// Illustrative examples for notes/part-10-course-appendix/35-agentic-security-baseline-workshop.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

/** Reject empty or floating versions; pin an exact version instead. */
function rejectFloating(version: string): void {
  const v = version.trim().toLowerCase();
  if (
    !v ||
    v === "latest" ||
    v === "*" ||
    v.startsWith("^") ||
    v.startsWith("~")
  ) {
    throw new Error(
      `floating or empty version "${version}" — pin exact version`,
    );
  }
}

export { rejectFloating };
