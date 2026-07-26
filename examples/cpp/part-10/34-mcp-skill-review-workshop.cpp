// Illustrative examples for notes/part-10-course-appendix/34-mcp-skill-review-workshop.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace {

// Учебные маркеры — не полный detector. В проде: отдельный review + policy.
const std::vector<std::string> kHostileMarkers = {
    "ignore previous",
    "system override",
    "do not tell the user",
};

std::string ToLower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return s;
}

bool DescriptionLooksHostile(const std::string& desc) {
  const std::string lower = ToLower(desc);
  for (const auto& marker : kHostileMarkers) {
    if (lower.find(marker) != std::string::npos) {
      return true;
    }
  }
  return false;
}

}  // namespace
