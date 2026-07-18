// Illustrative examples for notes/part-10-course-appendix/33-course-appendix-agentic-security.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

#include <stdexcept>
#include <string>
#include <unordered_set>

namespace {

const std::unordered_set<std::string> kAllowed = {"read_file", "repo_search"};

// Deny by default: tool must be in the allowlist.
void Authorize(const std::string& tool) {
  if (kAllowed.find(tool) == kAllowed.end()) {
    throw std::runtime_error("tool \"" + tool + "\" not in allowlist");
  }
}

}  // namespace
