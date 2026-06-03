---
tags: [ai-security, конспект]
часть: "Часть III — Защита обработки"
статус: черновик
---

# 07 — Parameter Validation и Schema Enforcement

> Навигация: [Оглавление](../../README.md) · [← Назад](06-rbac-tool-permissions.md) · [Вперёд →](08-sandboxing.md)

*Кратко: валидация аргументов инструментов по схеме (JSON Schema / Pydantic / CUE) — защита от LLM2Tool.*

## Суть

> TODO: зачем валидировать аргументы tool call по схеме.

## Угроза / контекст

> TODO: LLM2Tool — прямая передача вывода LLM в аргументы без фильтрации (главный вектор по исследованиям).

## Подходы и контрмеры

> TODO: JSON Schema, типы, диапазоны, sanitization аргументов перед вызовом.

## Пример (Go)

```go
// TODO: валидация аргументов инструмента по JSON Schema на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#инструменты)

## См. также

- [06 — RBAC и Tool Permissions](06-rbac-tool-permissions.md)
- [08 — Sandboxing](08-sandboxing.md)
