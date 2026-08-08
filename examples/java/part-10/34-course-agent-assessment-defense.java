// Illustrative examples for notes/part-10-course-appendix/34-course-agent-assessment-defense.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

import java.util.List;
import java.util.Map;

final class CourseAgentAssessmentDefense {
  private CourseAgentAssessmentDefense() {}

  private static final Map<String, List<String>> MAPPING =
      Map.of(
          "input", List.of("§03"),
          "output", List.of("§04", "§11"),
          "knowledge", List.of("§09", "§13"),
          "tools_mcp", List.of("§06", "§14", "§19"),
          "assurance", List.of("§20", "§38"));

  /** Map assessment area to handbook section anchors. */
  static List<String> handbookRefs(String area) {
    List<String> refs = MAPPING.get(area);
    if (refs == null) {
      throw new IllegalArgumentException("unknown area " + area);
    }
    return List.copyOf(refs);
  }

  /** Course assessment questions (#guardrail-assessment); scoring stays in §20. */
  static List<String> guardrailAssessmentHints() {
    return List.of(
        "ограничения (rails) на пути: input / retrieval / output / streaming?",
        "набор тестов (suite): легитимные (benign) + известные атаки (known-attack)?",
        "измерены ложные срабатывания / пропуски (FP / FN)?",
        "пороги зафиксированы (frozen) к прогону набора (suite run)?",
        "журнал изменений (changelog) при смене rail / threshold?",
        "агент может изготовить себе подтверждение (approval) / принять подделанное рассуждение (forged reasoning) за HITL? (§03/§14/§15; EV-12)");
  }
}
