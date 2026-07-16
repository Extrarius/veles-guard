#!/usr/bin/env bash
# Учебная эвристика: allowed-tools, danger-full-access, shell+network без approval.
# Не production-сканер — адаптируйте паттерны и пути.
#
# Usage: bash examples/bash/check-allowed-tools.sh [root-dir]
# Exit: 0 OK, 1 findings

set -euo pipefail

ROOT="${1:-.}"
FAILED=0

mapfile -t FILES < <(
  find "$ROOT" \
    \( -name 'mcp.json' -o -name 'mcp.*.json' -o -path '*/.cursor/mcp.json' \
       -o -name 'AGENTS.md' -o -name '*.agents.md' -o -name 'SKILL.md' \) \
    -type f 2>/dev/null || true
)

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "check-allowed-tools: no candidate config files under $ROOT (nothing to check)"
  exit 0
fi

for f in "${FILES[@]}"; do
  # danger-full-access / unrestricted tool grants
  if grep -EniE 'danger[-_ ]?full[-_ ]?access|full[_-]?access|unrestricted.?tools' "$f" >/dev/null 2>&1; then
    echo "FAIL: $f — danger-full-access / unrestricted tools marker"
    FAILED=1
  fi

  # shell + network together without an approval marker nearby (heuristic window)
  if grep -EniE '\b(shell|bash|cmd|powershell)\b' "$f" >/dev/null 2>&1 \
    && grep -EniE '\b(network|http|fetch|egress|internet)\b' "$f" >/dev/null 2>&1; then
    if ! grep -EniE 'approval|human.?in.?the.?loop|hitl|require.?confirm' "$f" >/dev/null 2>&1; then
      echo "FAIL: $f — shell and network mentioned without approval marker"
      FAILED=1
    fi
  fi

  # For skill/agent manifests: expect some allowlist mention if tools are granted
  base="$(basename "$f")"
  if [[ "$base" == "SKILL.md" || "$base" == "AGENTS.md" || "$base" == *.agents.md ]]; then
    if grep -EniE '\b(tools?|shell|filesystem|network)\b' "$f" >/dev/null 2>&1; then
      if ! grep -EniE 'allowed[-_ ]?tools|allowlist|permissions?' "$f" >/dev/null 2>&1; then
        echo "FAIL: $f — tools/capabilities mentioned but no allowed-tools / allowlist"
        FAILED=1
      fi
    fi
  fi
done

if [[ "$FAILED" -ne 0 ]]; then
  echo "check-allowed-tools: FAILED — tighten allowed-tools / approvals"
  exit 1
fi

echo "check-allowed-tools: OK (${#FILES[@]} file(s))"
exit 0
