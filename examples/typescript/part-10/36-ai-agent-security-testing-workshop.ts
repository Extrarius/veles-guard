// Illustrative examples for notes/part-10-course-appendix/36-ai-agent-security-testing-workshop.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

type Severity = "Critical" | "High" | "Medium" | "Low";

interface Finding {
  id: string;
  title: string;
  severity: Severity;
  area: string;
  expected: string;
  actual: string;
  fix?: string;
  regressionTest?: string;
}

/** Reject incomplete findings; Critical/High require a regression test. */
function validate(f: Finding): void {
  if (!f.id || !f.title) {
    throw new Error("id and title required");
  }
  if (!f.area || !f.severity) {
    throw new Error("area and severity required");
  }
  if (!f.expected || !f.actual) {
    throw new Error("expected and actual required");
  }
  if (
    (f.severity === "Critical" || f.severity === "High") &&
    !f.regressionTest
  ) {
    throw new Error(`${f.severity} finding requires regression test`);
  }
}

export { validate };
export type { Finding, Severity };
