// Illustrative examples for notes/part-10-course-appendix/33-course-appendix-agentic-security.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

import java.util.Set;

/** Deny by default: tool must be in the allowlist. */
class ToolAuthorize {
  private static final Set<String> ALLOWED = Set.of("read_file", "repo_search");

  static void authorize(String tool) {
    if (!ALLOWED.contains(tool)) {
      throw new IllegalArgumentException("tool \"" + tool + "\" not in allowlist");
    }
  }
}
