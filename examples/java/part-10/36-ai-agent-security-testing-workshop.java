// Illustrative examples for notes/part-10-course-appendix/36-ai-agent-security-testing-workshop.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

/** Reject incomplete findings; Critical/High require a regression test. */
class AgentSecurityFinding {
  String id;
  String title;
  String severity;
  String area;
  String expected;
  String actual;
  String fix;
  String regressionTest;

  static void validate(AgentSecurityFinding f) {
    if (f.id == null || f.id.isEmpty() || f.title == null || f.title.isEmpty()) {
      throw new IllegalArgumentException("id and title required");
    }
    if (f.area == null || f.area.isEmpty() || f.severity == null
        || f.severity.isEmpty()) {
      throw new IllegalArgumentException("area and severity required");
    }
    if (f.expected == null || f.expected.isEmpty() || f.actual == null
        || f.actual.isEmpty()) {
      throw new IllegalArgumentException("expected and actual required");
    }
    if (("Critical".equals(f.severity) || "High".equals(f.severity))
        && (f.regressionTest == null || f.regressionTest.isEmpty())) {
      throw new IllegalArgumentException(
          f.severity + " finding requires regression test");
    }
  }
}
