#!/usr/bin/env bash
# Учебный сниппет для notes/part-10-course-appendix/33-course-ai-security-landscape.md
# Навигатор слоя системы → якоря разделов частей I–IX. Не для production.
# Licensed under MIT (see LICENSE-CODE).
#
# Usage: bash examples/bash/part-10/33-course-ai-security-landscape.sh <layer>
# Layers: interface | app_control | ai_knowledge | execution | assurance

set -euo pipefail

LAYER="${1:-}"

if [[ -z "$LAYER" ]]; then
  echo "usage: $0 <interface|app_control|ai_knowledge|execution|assurance>" >&2
  exit 2
fi

case "$LAYER" in
  interface) echo "§03 §04 §05" ;;
  app_control) echo "§06 §07 §14 §17" ;;
  ai_knowledge) echo "§04 §09 §11 §12 §13" ;;
  execution) echo "§08 §18 §19 §22 §28 §31" ;;
  assurance) echo "§15 §16 §20 §21 §23" ;;
  *)
    echo "FAIL: unknown layer '$LAYER'" >&2
    exit 1
    ;;
esac
