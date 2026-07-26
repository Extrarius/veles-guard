// Illustrative examples for notes/part-10-course-appendix/34-mcp-skill-review-workshop.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

// Учебные маркеры — не полный detector. В проде: отдельный review + policy.
const hostileMarkers = [
  "ignore previous",
  "system override",
  "do not tell the user",
] as const;

function descriptionLooksHostile(desc: string): boolean {
  const lower = desc.toLowerCase();
  return hostileMarkers.some((marker) => lower.includes(marker));
}

export { descriptionLooksHostile, hostileMarkers };
