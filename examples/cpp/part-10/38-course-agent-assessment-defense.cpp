// Illustrative examples for notes/part-10-course-appendix/38-course-agent-assessment-defense.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

#include <stdexcept>
#include <string>
#include <vector>

inline std::vector<std::string> handbookRefs(const std::string& area) {
  if (area == "input")
    return {"§03"};
  if (area == "output")
    return {"§04", "§11"};
  if (area == "knowledge")
    return {"§09", "§13"};
  if (area == "tools_mcp")
    return {"§06", "§14", "§19"};
  if (area == "assurance")
    return {"§20", "§37"};
  throw std::invalid_argument("unknown area");
}
