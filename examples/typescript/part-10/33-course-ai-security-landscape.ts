// Illustrative examples for notes/part-10-course-appendix/33-course-ai-security-landscape.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

type Layer =
  | "interface"
  | "app_control"
  | "ai_knowledge"
  | "execution"
  | "assurance";

const MAPPING: Record<Layer, string[]> = {
  interface: ["§03", "§04", "§05"],
  app_control: ["§06", "§07", "§14", "§17"],
  ai_knowledge: ["§04", "§09", "§11", "§12", "§13"],
  execution: ["§08", "§18", "§19", "§22", "§28", "§31"],
  assurance: ["§15", "§16", "§20", "§21", "§23"],
};

/** Map system layer to handbook section anchors (parts I–IX). */
function sectionRefs(layer: Layer): string[] {
  const refs = MAPPING[layer];
  if (!refs) {
    throw new Error(`unknown layer ${layer}`);
  }
  return [...refs];
}

export { sectionRefs };
export type { Layer };
