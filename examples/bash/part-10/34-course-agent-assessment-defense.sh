#!/usr/bin/env bash
# Учебный сниппет для notes/part-10-course-appendix/34-course-agent-assessment-defense.md
# Область assessment → якоря разделов. Не для production.
# Licensed under MIT (see LICENSE-CODE).
#
# Usage: bash examples/bash/part-10/34-course-agent-assessment-defense.sh <area>
# Areas: input | output | knowledge | tools_mcp | assurance

set -euo pipefail

AREA="${1:-}"

if [[ -z "$AREA" ]]; then
  echo "usage: $0 <input|output|knowledge|tools_mcp|assurance>" >&2
  exit 2
fi

case "$AREA" in
  input) echo "§03" ;;
  output) echo "§04 §11" ;;
  knowledge) echo "§09 §13" ;;
  tools_mcp) echo "§06 §14 §19" ;;
  assurance) echo "§20 §38" ;;
  *)
    echo "FAIL: unknown area '$AREA'" >&2
    exit 1
    ;;
esac
