// Illustrative examples for notes/part-10-course-appendix/35-agentic-security-baseline-workshop.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

/** Reject empty or floating versions; pin an exact version instead. */
class VersionPin {
  static void rejectFloating(String version) {
    String v = version.trim().toLowerCase();
    if (v.isEmpty()
        || v.equals("latest")
        || v.equals("*")
        || v.startsWith("^")
        || v.startsWith("~")) {
      throw new IllegalArgumentException(
          "floating or empty version \"" + version + "\" — pin exact version");
    }
  }
}
