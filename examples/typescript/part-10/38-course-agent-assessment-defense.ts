// Illustrative examples for notes/part-10-course-appendix/38-course-agent-assessment-defense.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

type Area = "input" | "output" | "knowledge" | "tools_mcp" | "assurance";

const MAPPING: Record<Area, string[]> = {
  input: ["§03"],
  output: ["§04", "§11"],
  knowledge: ["§09", "§13"],
  tools_mcp: ["§06", "§14", "§19"],
  assurance: ["§20", "§37"],
};

/** Map assessment area to handbook section anchors. */
function handbookRefs(area: Area): string[] {
  const refs = MAPPING[area];
  if (!refs) {
    throw new Error(`unknown area ${area}`);
  }
  return [...refs];
}

type GuardrailMode = "hard" | "soft";

export { handbookRefs };
export type { Area, GuardrailMode };
