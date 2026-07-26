---
tags: [ai-security, шаблон, course, finding, testing, workshop]
статус: шаблон
---

# Course: карточка finding, воркшоп

[← Оглавление](../../README.md)

> Учебная обёртка. Основная форма — [templates/agent-security-finding.md](../agent-security-finding.md).  
> Канон процесса — [guides/ai-agent-security-testing-guide.md](../../guides/ai-agent-security-testing-guide.md).  
> Воркшоп: [§36](../../notes/part-10-course-appendix/36-ai-agent-security-testing-workshop.md).

## Как использовать на занятии

1. Открыть [Testing Guide](../../guides/ai-agent-security-testing-guide.md): Scope + Rules of Engagement (2–3 мин).
2. Выбрать **3–4** строки из Test Matrix под ваш учебный агент / sandbox.
3. На каждую выбранную строку: Expected (как должно быть) → Actual (что увидели / что проверили в mock).
4. Оформить **1–2** finding в [agent-security-finding.md](../agent-security-finding.md).
5. Для Critical/High обязательно заполнить **Fix** и **Regression test**.
6. Собрать короткий Report: summary → high-risk → blocked → checklist / red-team updates.

## Быстрые правила

- Только свой агент / sandbox; без реальных секретов и внешних destructive actions.
- Проверки формулировать позитивно («агент НЕ…», «egress блокирует…»).
- Не приносить в чат курса offensive payload dump.
- Finding без Evidence — не finding.

## Severity (шпаргалка)

| Severity | Пример |
|---|---|
| Critical | sandbox escape, успешный egress exfiltration |
| High | tool без approval, утечка секрета в output |
| Medium | пробел в логах при компенсациях |
| Low | нет owner/inventory при низком риске |

## См. также

- [mcp-skill-review.md](mcp-skill-review.md)
- [agentic-security-baseline.md](agentic-security-baseline.md)
- [incident-card-mcp-skill.md](incident-card-mcp-skill.md)
- [20 — Red Teaming](../../notes/part-7-testing-compliance/20-red-teaming-adversarial-testing.md)
