---
tags: [ai-security, шаблон, finding, testing, review]
статус: шаблон
---

# Шаблон: Agent Security Finding

[← Оглавление](../README.md)

> Заполняемая карточка finding по результатам проверки AI-агента. Процесс — [guides/ai-agent-security-testing-guide.md](../guides/ai-agent-security-testing-guide.md). Учебная обёртка — [templates/course/agent-security-finding.md](course/agent-security-finding.md).

## Identity

- **ID:** `<ASF-YYYY-NNN>`
- **Title:** `<короткое название>`
- **Date:** `<YYYY-MM-DD>`
- **Author:** `<...>`
- **Target:** `<agent / env / version>`

## Classification

- **Severity:** `<Critical / High / Medium / Low>`
- **Area:** `<input / context / tools / memory / sandbox / egress / output / MCP / AI-coding>`
- **Status:** `<open / fixed / accepted-risk / duplicate>`

## Scenario

- **Scenario (что проверяли):** `<позитивная формулировка: «проверить, что…»>`
- **Expected:** `<как должно быть по политике>`
- **Actual:** `<что произошло>`

## Evidence

- **Evidence:** `<logs / trace ID / screenshot / diff — без секретов и offensive payload>`
- **Repro notes:** `<минимальные шаги в sandbox; без атак на чужие системы>`

## Remediation

- **Fix:** `<что исправить>`
- **Owner:** `<...>`
- **Due date:** `<YYYY-MM-DD>`
- **Regression test:** `<ID теста / CI job / путь к кейсу>`
- **Handbook refs:** `<§20 / §23 / §25 / §32 / …>`

## Decision

- **Production impact:** `<blocked / not blocked>`
- **Checklist updates:** `<что добавить в §25 / §32>`
- **Red team suite updates:** `<что добавить в §20 suite>`

## См. также

- [guides/ai-agent-security-testing-guide.md](../guides/ai-agent-security-testing-guide.md)
- [incident-report-template.md](incident-report-template.md) — если finding уже инцидент
- [mcp-skill-review.md](mcp-skill-review.md) — если область = MCP / skill
