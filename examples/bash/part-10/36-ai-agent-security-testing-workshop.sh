#!/usr/bin/env bash
# Учебный сниппет для notes/part-10-course-appendix/36-ai-agent-security-testing-workshop.md
# Проверка обязательных полей finding; Critical/High требуют regression test.
# Licensed under MIT (see LICENSE-CODE).
#
# Usage:
#   bash examples/bash/part-10/36-ai-agent-security-testing-workshop.sh \
#     <id> <severity> <area> <expected> <actual> [regression_test]
# Exit: 0 OK, 1 validation failed

set -euo pipefail

ID="${1:-}"
SEVERITY="${2:-}"
AREA="${3:-}"
EXPECTED="${4:-}"
ACTUAL="${5:-}"
REGRESSION="${6:-}"

if [[ -z "$ID" ]]; then
  echo "FAIL: id required" >&2
  exit 1
fi

if [[ -z "$SEVERITY" || -z "$AREA" ]]; then
  echo "FAIL: area and severity required" >&2
  exit 1
fi

if [[ -z "$EXPECTED" || -z "$ACTUAL" ]]; then
  echo "FAIL: expected and actual required" >&2
  exit 1
fi

case "$SEVERITY" in
  Critical|High)
    if [[ -z "$REGRESSION" ]]; then
      echo "FAIL: $SEVERITY finding requires regression test" >&2
      exit 1
    fi
    ;;
  Medium|Low) ;;
  *)
    echo "FAIL: unknown severity '$SEVERITY'" >&2
    exit 1
    ;;
esac

echo "OK: finding '$ID' ($SEVERITY / $AREA) looks complete"
exit 0
