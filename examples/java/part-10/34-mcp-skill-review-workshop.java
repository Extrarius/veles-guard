// Illustrative examples for notes/part-10-course-appendix/34-mcp-skill-review-workshop.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

/** Учебные маркеры — не полный detector. В проде: отдельный review + policy. */
class DescriptionReview {
  private static final String[] HOSTILE_MARKERS = {
    "ignore previous",
    "system override",
    "do not tell the user",
  };

  static boolean descriptionLooksHostile(String desc) {
    String lower = desc.toLowerCase();
    for (String marker : HOSTILE_MARKERS) {
      if (lower.contains(marker)) {
        return true;
      }
    }
    return false;
  }
}
