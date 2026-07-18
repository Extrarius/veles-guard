#!/usr/bin/env bash
# Учебный сниппет для notes/part-10-course-appendix/33-course-appendix-agentic-security.md
# Порт идеи deny-by-default / allowlist tools. Не для production.
# Licensed under MIT (see LICENSE-CODE).
#
# Usage: bash examples/bash/part-10/33-course-appendix-agentic-security.sh <tool-name>
# Exit: 0 OK, 1 not in allowlist

set -euo pipefail

TOOL="${1:-}"

if [[ -z "$TOOL" ]]; then
  echo "usage: $0 <tool-name>" >&2
  exit 2
fi

# Белый список (allowlist) — явно разрешённые инструменты
case "$TOOL" in
  read_file|repo_search)
    echo "OK: tool '$TOOL' in allowlist"
    exit 0
    ;;
  *)
    echo "FAIL: tool '$TOOL' not in allowlist" >&2
    exit 1
    ;;
esac
