// Illustrative examples for notes/part-10-course-appendix/35-agentic-security-baseline-workshop.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>

namespace {

std::string TrimLower(std::string s) {
  auto not_space = [](unsigned char c) { return !std::isspace(c); };
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
  s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return s;
}

// Reject empty or floating versions; pin an exact version instead.
void RejectFloating(const std::string& version) {
  const std::string v = TrimLower(version);
  if (v.empty() || v == "latest" || v == "*" ||
      (!v.empty() && (v[0] == '^' || v[0] == '~'))) {
    throw std::runtime_error("floating or empty version \"" + version +
                             "\" — pin exact version");
  }
}

}  // namespace
