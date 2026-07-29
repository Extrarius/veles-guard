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
}
