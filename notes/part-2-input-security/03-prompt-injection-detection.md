---
tags: [ai-security, конспект]
часть: "Часть II — Защита на входе"
статус: черновик
---

# 03 — Prompt Injection Detection

> Навигация: [Оглавление](../../README.md) · [← Назад](../part-1-architecture-threats/02-threat-model.md) · [Вперёд →](04-pii-redaction-content-filtering.md)

*Кратко: суть атаки (Direct vs Indirect) и подходы к детектированию — rule-based, ML-based, LLM-as-Judge.*

## Суть

> TODO: что такое prompt injection, почему данные смешиваются с инструкциями.

## Угроза / контекст

> TODO: Direct vs Indirect injection; инъекции из веб-страниц, писем, документов, RAG.

## Подходы и контрмеры

> TODO: rule-based эвристики, ML-детекторы (Lakera, Rebuff, Prompt Guard), LLM-as-Judge, разделение trusted/untrusted контекста.

## Пример (Go)

```go
// TODO: эвристический фильтр инъекций + вызов классификатора на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#prompt-injection)

## См. также

- [13 — Egress Control и Data Exfiltration](../part-4-output-security/13-egress-control-data-exfiltration.md)
- [09 — Memory Isolation и Context Sanitization](../part-3-processing-security/09-memory-isolation-context-sanitization.md)
