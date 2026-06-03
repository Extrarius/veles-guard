---
tags: [ai-security, конспект]
часть: "Часть V — Контроль и наблюдаемость"
статус: черновик
---

# 14 — Human-in-the-Loop

> Навигация: [Оглавление](../../README.md) · [← Назад](../part-4-output-security/13-egress-control-data-exfiltration.md) · [Вперёд →](15-observability-tracing.md)

*Кратко: approval workflows и эскалация — пауза перед критичными операциями.*

## Суть

> TODO: human-in-the-loop, когда требовать одобрение.

## Угроза / контекст

> TODO: опасные действия (удаление, платежи, письма, shell), human-agent trust exploitation.

## Подходы и контрмеры

> TODO: approval workflows, action risk levels (safe/sensitive/dangerous), confirmation step.

## Пример (Go)

```go
// TODO: middleware паузы и запроса одобрения перед опасным действием на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#практические-руководства)

## См. также

- [06 — RBAC и Tool Permissions](../part-3-processing-security/06-rbac-tool-permissions.md)
- [17 — Circuit Breaker и Kill-Switch](17-circuit-breaker-kill-switch.md)
