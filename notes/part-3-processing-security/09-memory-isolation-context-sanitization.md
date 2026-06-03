---
tags: [ai-security, конспект]
часть: "Часть III — Защита обработки"
статус: черновик
---

# 09 — Memory Isolation и Context Sanitization

> Навигация: [Оглавление](../../README.md) · [← Назад](08-sandboxing.md) · [Вперёд →](10-secrets-management.md)

*Кратко: разделение контекста между сессиями/пользователями и проверка целостности RAG-данных.*

## Суть

> TODO: изоляция памяти, очистка контекста, целостность долговременной памяти.

## Угроза / контекст

> TODO: memory/knowledge poisoning, перепутывание сессий, инъекции из RAG.

## Подходы и контрмеры

> TODO: namespace-изоляция в vector store, integrity checks, context sanitization, session isolation.

## Пример (Go)

```go
// TODO: namespace-изоляция памяти по сессии/пользователю на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#академические-исследования)

## См. также

- [03 — Prompt Injection Detection](../part-2-input-security/03-prompt-injection-detection.md)
- [22 — Supply Chain Security](../part-7-testing-compliance/22-supply-chain-security.md)
