---
tags: [ai-security, конспект]
часть: "Часть V — Контроль и наблюдаемость"
статус: черновик
---

# 16 — Monitoring и Alerting

> Навигация: [Оглавление](../../README.md) · [← Назад](15-observability-tracing.md) · [Вперёд →](17-circuit-breaker-kill-switch.md)

*Кратко: метрики (latency, error rate, tool usage, cost) и алерты на аномалии.*

## Суть

> TODO: какие метрики собирать и как алертить.

## Угроза / контекст

> TODO: незамеченное аномальное поведение, рост стоимости, аномальные tool calls.

## Подходы и контрмеры

> TODO: Prometheus + Grafana, алерты по порогам, runtime protection.

## Пример (Go)

```go
// TODO: экспорт метрик агента в Prometheus на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#инструменты)

## См. также

- [15 — Observability и Tracing](15-observability-tracing.md)
- [05 — Rate Limiting, Quotas и Token Bombing](../part-2-input-security/05-rate-limiting-quotas-token-bombing.md)
