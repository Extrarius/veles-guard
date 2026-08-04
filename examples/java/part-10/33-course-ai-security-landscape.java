// Illustrative examples for notes/part-10-course-appendix/33-course-ai-security-landscape.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

import java.util.List;
import java.util.Map;

final class CourseAiSecurityLandscape {
  private CourseAiSecurityLandscape() {}

  private static final Map<String, List<String>> MAPPING =
      Map.of(
          "interface", List.of("§03", "§04", "§05"),
          "app_control", List.of("§06", "§07", "§14", "§17"),
          "ai_knowledge", List.of("§04", "§09", "§11", "§12", "§13"),
          "execution", List.of("§08", "§18", "§19", "§22", "§28", "§31"),
          "assurance", List.of("§15", "§16", "§20", "§21", "§23"));

  /** Map system layer to handbook section anchors (parts I–IX). */
  static List<String> sectionRefs(String layer) {
    List<String> refs = MAPPING.get(layer);
    if (refs == null) {
      throw new IllegalArgumentException("unknown layer " + layer);
    }
    return List.copyOf(refs);
  }
}
