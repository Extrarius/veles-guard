// Illustrative examples for notes/part-10-course-appendix/34-course-agent-assessment-defense.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

type Area = "input" | "output" | "knowledge" | "tools_mcp" | "assurance";

const MAPPING: Record<Area, string[]> = {
  input: ["§03"],
  output: ["§04", "§11"],
  knowledge: ["§09", "§13"],
  tools_mcp: ["§06", "§14", "§19"],
  assurance: ["§20", "§38"],
};

/** Map assessment area to handbook section anchors. */
function handbookRefs(area: Area): string[] {
  const refs = MAPPING[area];
  if (!refs) {
    throw new Error(`unknown area ${area}`);
  }
  return [...refs];
}

/** Course assessment questions (#guardrail-assessment); scoring stays in §20. */
function guardrailAssessmentHints(): string[] {
  return [
    "ограничения (rails) на пути: input / retrieval / output / streaming?",
    "набор тестов (suite): легитимные (benign) + известные атаки (known-attack)?",
    "измерены ложные срабатывания / пропуски (FP / FN)?",
    "пороги зафиксированы (frozen) к прогону набора (suite run)?",
    "журнал изменений (changelog) при смене rail / threshold?",
    "агент может изготовить себе подтверждение (approval) / принять подделанное рассуждение (forged reasoning) за HITL? (§03/§14/§15; EV-12)",
  ];
}

type GuardrailMode = "hard" | "soft";

export { handbookRefs, guardrailAssessmentHints };
export type { Area, GuardrailMode };
