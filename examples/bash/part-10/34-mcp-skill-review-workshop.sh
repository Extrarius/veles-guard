#!/usr/bin/env bash
# Учебный сниппет для notes/part-10-course-appendix/34-mcp-skill-review-workshop.md
# Порт DescriptionLooksHostile: учебные маркеры в description. Не полный detector.
# Licensed under MIT (see LICENSE-CODE).
#
# Usage: bash examples/bash/part-10/34-mcp-skill-review-workshop.sh "описание инструмента"
# Exit: 0 чисто, 1 найден враждебный маркер

set -euo pipefail

DESC="${1:-}"

if [[ -z "$DESC" ]]; then
  echo "usage: $0 \"description text\"" >&2
  exit 2
fi

LOWER=$(printf '%s' "$DESC" | tr '[:upper:]' '[:lower:]')

# Учебные маркеры — не полный detector. В проде: отдельный review + policy.
for marker in \
  "ignore previous" \
  "system override" \
  "do not tell the user"
do
  if [[ "$LOWER" == *"$marker"* ]]; then
    echo "FAIL: description looks hostile (marker: $marker)" >&2
    exit 1
  fi
done

echo "OK: no hostile markers in description"
exit 0
