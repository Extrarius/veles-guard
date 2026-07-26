// Illustrative examples for notes/part-10-course-appendix/36-ai-agent-security-testing-workshop.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

#include <stdexcept>
#include <string>

namespace {

struct Finding {
  std::string id;
  std::string title;
  std::string severity;
  std::string area;
  std::string expected;
  std::string actual;
  std::string fix;
  std::string regression_test;
};

// Reject incomplete findings; Critical/High require a regression test.
void Validate(const Finding& f) {
  if (f.id.empty() || f.title.empty()) {
    throw std::runtime_error("id and title required");
  }
  if (f.area.empty() || f.severity.empty()) {
    throw std::runtime_error("area and severity required");
  }
  if (f.expected.empty() || f.actual.empty()) {
    throw std::runtime_error("expected and actual required");
  }
  if ((f.severity == "Critical" || f.severity == "High") &&
      f.regression_test.empty()) {
    throw std::runtime_error(f.severity +
                             " finding requires regression test");
  }
}

}  // namespace
