---
tags: [ai-security, конспект]
часть: "Часть II — Защита на входе"
статус: черновик
---

# 04 — PII Redaction и Content Filtering

> Навигация: [Оглавление](../../README.md) · [← Назад](03-prompt-injection-detection.md) · [Вперёд →](05-rate-limiting-quotas-token-bombing.md)

*Кратко: анонимизация персональных данных (Presidio / scrubadub) и фильтрация контента перед передачей в LLM.*

## Суть

> TODO: зачем маскировать PII и фильтровать контент на входе.

## Угроза / контекст

> TODO: утечка PII в LLM-провайдера, токсичный/опасный контент.

## Подходы и контрмеры

> TODO: Microsoft Presidio, scrubadub, toxicity-фильтры; pipeline redaction перед LLM.

## Пример (Go)

```go
// TODO: pipeline маскирования PII перед вызовом LLM на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#инструменты)

## См. также

- [10 — Secrets Management](../part-3-processing-security/10-secrets-management.md)
- [13 — Egress Control и Data Exfiltration](../part-4-output-security/13-egress-control-data-exfiltration.md)
