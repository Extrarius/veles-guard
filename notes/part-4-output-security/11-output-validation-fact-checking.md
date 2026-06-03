---
tags: [ai-security, конспект]
часть: "Часть IV — Защита на выходе"
статус: черновик
---

# 11 — Output Validation и Fact-Checking

> Навигация: [Оглавление](../../README.md) · [← Назад](../part-3-processing-security/10-secrets-management.md) · [Вперёд →](12-hallucination-detection.md)

*Кратко: structured outputs (JSON mode, function calling) и RAG-grounding для проверки фактов в выводе.*

## Суть

> TODO: валидация структуры и фактов вывода LLM.

## Угроза / контекст

> TODO: output manipulation, передача невалидного/опасного вывода дальше.

## Подходы и контрмеры

> TODO: structured outputs, JSON schema, Guardrails AI / Pydantic, RAG-grounding.

## Пример (Go)

```go
// TODO: валидация структурированного вывода по схеме на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#инструменты)

## См. также

- [12 — Hallucination Detection](12-hallucination-detection.md)
- [07 — Parameter Validation и Schema Enforcement](../part-3-processing-security/07-parameter-validation-schema.md)
