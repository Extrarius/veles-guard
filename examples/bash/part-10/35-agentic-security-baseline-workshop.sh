#!/usr/bin/env bash
# Учебный сниппет для notes/part-10-course-appendix/35-agentic-security-baseline-workshop.md
# Порт RejectFloating: запрет latest / * / ^ / ~ / пустой версии. Не дубль verify-pins.sh.
# Licensed under MIT (see LICENSE-CODE).
#
# Usage: bash examples/bash/part-10/35-agentic-security-baseline-workshop.sh <version>
# Exit: 0 pinned OK, 1 floating/empty

set -euo pipefail

VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
  echo "FAIL: empty version — pin exact version" >&2
  exit 1
fi

# Нормализуем для сравнения
V=$(printf '%s' "$VERSION" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

case "$V" in
  latest|\*)
    echo "FAIL: floating version '$VERSION' — pin exact version" >&2
    exit 1
    ;;
esac

if [[ "$V" == ^* || "$V" == ~* ]]; then
  echo "FAIL: floating version '$VERSION' — pin exact version" >&2
  exit 1
fi

echo "OK: version '$VERSION' looks pinned"
exit 0
