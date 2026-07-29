// Illustrative examples for notes/part-10-course-appendix/33-course-ai-security-landscape.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

#include <stdexcept>
#include <string>
#include <vector>

inline std::vector<std::string> sectionRefs(const std::string& layer) {
  if (layer == "interface")
    return {"§03", "§04", "§05"};
  if (layer == "app_control")
    return {"§06", "§07", "§14", "§17"};
  if (layer == "ai_knowledge")
    return {"§04", "§09", "§11", "§12", "§13"};
  if (layer == "execution")
    return {"§08", "§18", "§19", "§22", "§28", "§31"};
  if (layer == "assurance")
    return {"§15", "§16", "§20", "§21", "§23"};
  throw std::invalid_argument("unknown layer");
}
