#!/usr/bin/env bash
# Учебная проверка: нет latest / * / floating (^ ~) в типичных MCP/skill-конфигах.
# Адаптируйте ROOT и GLOBS под свой layout. Не production-сканер.
#
# Usage: bash examples/bash/verify-pins.sh [root-dir]
# Exit: 0 OK, 1 findings

set -euo pipefail

ROOT="${1:-.}"
FAILED=0

# Типичные пути — расширьте под проект
mapfile -t FILES < <(
  find "$ROOT" \
    \( -name 'mcp.json' -o -name 'mcp.*.json' -o -path '*/.cursor/mcp.json' \) \
    -type f 2>/dev/null || true
)

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "verify-pins: no mcp.json-like files under $ROOT (nothing to check)"
  exit 0
fi

check_file() {
  local f="$1"
  # latest as version token
  if grep -EniE '(["'\'']?version["'\'']?\s*[:=]\s*["'\'']?latest["'\'']?)|(@latest\b)|([:=]\s*["'\'']latest["'\''])' "$f" >/dev/null 2>&1; then
    echo "FAIL: $f — contains 'latest'"
    FAILED=1
  fi
  # wildcard version
  if grep -EnE '(["'\'']version["'\'']\s*:\s*["'\'']\*|version\s*=\s*\*)' "$f" >/dev/null 2>&1; then
    echo "FAIL: $f — contains wildcard version '*'"
    FAILED=1
  fi
  # floating ^ or ~ in version strings (npm-style)
  if grep -EnE '(["'\'']version["'\'']\s*:\s*["'\''][\^~])' "$f" >/dev/null 2>&1; then
    echo "FAIL: $f — floating version (^ or ~)"
    FAILED=1
  fi
}

for f in "${FILES[@]}"; do
  check_file "$f"
done

if [[ "$FAILED" -ne 0 ]]; then
  echo "verify-pins: FAILED — pin versions; do not use latest / * / ^ / ~"
  exit 1
fi

echo "verify-pins: OK (${#FILES[@]} file(s))"
exit 0
