#!/usr/bin/env bash
# Учебный сниппет для notes/part-10-course-appendix/34-course-agent-assessment-defense.md
# Область assessment → якоря разделов; либо подсказки Guardrail assessment.
# Не для production. Licensed under MIT (see LICENSE-CODE).
#
# Usage:
#   bash examples/bash/part-10/34-course-agent-assessment-defense.sh <area>
#   bash examples/bash/part-10/34-course-agent-assessment-defense.sh hints
# Areas: input | output | knowledge | tools_mcp | assurance

set -euo pipefail

CMD="${1:-}"

if [[ -z "$CMD" ]]; then
  echo "usage: $0 <input|output|knowledge|tools_mcp|assurance|hints>" >&2
  exit 2
fi

if [[ "$CMD" == "hints" ]]; then
  cat <<'EOF'
ограничения (rails) на пути: input / retrieval / output / streaming?
набор тестов (suite): легитимные (benign) + известные атаки (known-attack)?
измерены ложные срабатывания / пропуски (FP / FN)?
пороги зафиксированы (frozen) к прогону набора (suite run)?
журнал изменений (changelog) при смене rail / threshold?
агент может изготовить себе подтверждение (approval) / принять подделанное рассуждение (forged reasoning) за HITL? (§03/§14/§15; EV-12)
EOF
  exit 0
fi

case "$CMD" in
  input) echo "§03" ;;
  output) echo "§04 §11" ;;
  knowledge) echo "§09 §13" ;;
  tools_mcp) echo "§06 §14 §19" ;;
  assurance) echo "§20 §38" ;;
  *)
    echo "FAIL: unknown area '$CMD'" >&2
    exit 1
    ;;
esac
