---
tags: [ai-security, конспект]
часть: "Часть V — Контроль и наблюдаемость"
статус: черновик
---

# 15 — Observability и Tracing

> Навигация: [Оглавление](../../README.md) · [← Назад](14-human-in-the-loop.md) · [Вперёд →](16-monitoring-alerting.md)

*Кратко: трассировка шагов агента — OpenTelemetry GenAI, Langfuse, LangSmith.*

## Суть

> TODO: зачем нужна наблюдаемость, что трассировать (model/tool calls, токены, prompts).

## Угроза / контекст

> TODO: невозможность разобрать инцидент без трассировки и аудита.

## Подходы и контрмеры

> TODO: OpenTelemetry GenAI semantic conventions, Langfuse/LangSmith, immutable audit trails, tamper-resistant logs.

## Пример (Go)

```go
// TODO: инструментация агента через OpenTelemetry на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#инструменты)

## См. также

- [16 — Monitoring и Alerting](16-monitoring-alerting.md)
- [23 — Incident Response и Recovery](../part-7-testing-compliance/23-incident-response-recovery.md)
