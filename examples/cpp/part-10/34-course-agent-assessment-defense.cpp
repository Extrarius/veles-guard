// Illustrative examples for notes/part-10-course-appendix/34-course-agent-assessment-defense.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

#include <stdexcept>
#include <string>
#include <vector>

inline std::vector<std::string> handbookRefs(const std::string& area) {
  if (area == "input")
    return {"§03"};
  if (area == "output")
    return {"§04", "§11"};
  if (area == "knowledge")
    return {"§09", "§13"};
  if (area == "tools_mcp")
    return {"§06", "§14", "§19"};
  if (area == "assurance")
    return {"§20", "§38"};
  throw std::invalid_argument("unknown area");
}

/** Course assessment questions (#guardrail-assessment); scoring stays in §20. */
inline std::vector<std::string> guardrailAssessmentHints() {
  return {
      "ограничения (rails) на пути: input / retrieval / output / streaming?",
      "набор тестов (suite): легитимные (benign) + известные атаки (known-attack)?",
      "измерены ложные срабатывания / пропуски (FP / FN)?",
      "пороги зафиксированы (frozen) к прогону набора (suite run)?",
      "журнал изменений (changelog) при смене rail / threshold?",
      "агент может изготовить себе подтверждение (approval) / принять подделанное рассуждение (forged reasoning) за HITL? (§03/§14/§15; EV-12)",
  };
}
