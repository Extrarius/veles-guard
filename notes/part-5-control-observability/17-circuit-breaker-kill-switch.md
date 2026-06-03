---
tags: [ai-security, конспект]
часть: "Часть V — Контроль и наблюдаемость"
статус: черновик
---

# 17 — Circuit Breaker и Kill-Switch

> Навигация: [Оглавление](../../README.md) · [← Назад](16-monitoring-alerting.md) · [Вперёд →](../part-6-multi-agent-security/18-inter-agent-security.md)

*Кратко: аварийная остановка агента при аномалиях, паттерн fail-closed.*

## Суть

> TODO: circuit breaker, kill-switch, fail-closed by default.

## Угроза / контекст

> TODO: cascading failures, rogue agents, отсутствие аварийной остановки.

## Подходы и контрмеры

> TODO: circuit breaker, emergency stop, rollback/undo, fail-closed.

## Пример (Go)

```go
// TODO: реализация circuit breaker на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#стандарты-и-фреймворки)

## См. также

- [14 — Human-in-the-Loop](14-human-in-the-loop.md)
- [23 — Incident Response и Recovery](../part-7-testing-compliance/23-incident-response-recovery.md)
