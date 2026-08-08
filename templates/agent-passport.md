---
tags: [ai-security, шаблон, passport, agent-risk]
статус: шаблон
---

# Шаблон: Agent Passport

[← Оглавление](../README.md)

> Спецификация агента **до запуска** (агент как продукт). Класс риска и обязательные контроли: [§25 — Класс риска агента (R0–R3)](../notes/part-8-practice/25-security-by-design-checklist.md#agent-risk-class). Ops-минимум MCP/skills — [agentic-security-baseline.md](agentic-security-baseline.md), не замена паспорта.

| Поле | Значение |
|---|---|
| **Agent name / ID** | `<...>` |
| **Owner (human)** | `<имя>` |
| **Team** | `<...>` |
| **Purpose** | `<зачем агент>` |
| **Out of scope** | `<чего агент не делает>` |
| **Risk class** | `R0` \| `R1` \| `R2` \| `R3` |
| **Risk rationale** | `<почему этот класс>` |
| **Data classes (D0–D4)** | `<...>` · `ai_allowed` / ограничения |
| **Models / inference path** | `<model>` · через AI Gateway / proxy: Yes / No |
| **Tools / MCP** | `<список>` · registry refs: `<...>` |
| **Acting mode** | propose-only / act-with-approval / … |
| **Approval policy** | `<какие действия требуют HITL>` |
| **Kill-switch owner** | `<...>` |
| **IR / runbook** | `<ссылка>` |
| **Review date** | `<YYYY-MM-DD>` |
| **Next review** | `<YYYY-MM-DD>` |

## Подписи

| Роль | Имя | Дата |
|---|---|---|
| Owner | | |
| Security review | | |
| (R3) Compliance / risk | | |

## См. также

- [25 — Security-by-Design / R0–R3](../notes/part-8-practice/25-security-by-design-checklist.md#agent-risk-class)
- [agentic-security-baseline.md](agentic-security-baseline.md) — pin / sandbox / egress для MCP и skills
- [21 — Compliance](../notes/part-7-testing-compliance/21-compliance-standards.md) — при R3
- [04 — D0–D4](../notes/part-2-input-security/04-pii-redaction-content-filtering.md#ai-data-classes-d0-d4)
