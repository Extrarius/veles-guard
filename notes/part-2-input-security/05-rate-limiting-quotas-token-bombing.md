---
tags: [ai-security, конспект]
часть: "Часть II — Защита на входе"
статус: черновик
---

# 05 — Rate Limiting, Quotas и Token Bombing

> Навигация: [Оглавление](../../README.md) · [← Назад](04-pii-redaction-content-filtering.md) · [Вперёд →](../part-3-processing-security/06-rbac-tool-permissions.md)

*Кратко: лимиты запросов и бюджетов (token bucket / sliding window) и защита от cost-атак / token bombing.*

## Суть

> TODO: rate limiting, quotas, token/spending budgets.

## Угроза / контекст

> TODO: DoS, финансовые атаки (token bombing / cost attack), дорогие запросы.

## Подходы и контрмеры

> TODO: token bucket, sliding window, лимиты токенов/денег/времени, throttling.

## Пример (Go)

```go
// TODO: rate limiting middleware (token bucket) на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#инструменты)

## См. также

- [17 — Circuit Breaker и Kill-Switch](../part-5-control-observability/17-circuit-breaker-kill-switch.md)
- [16 — Monitoring и Alerting](../part-5-control-observability/16-monitoring-alerting.md)
