---
tags: [ai-security, конспект]
часть: "Часть III — Защита обработки"
статус: черновик
---

# 10 — Secrets Management

> Навигация: [Оглавление](../../README.md) · [← Назад](09-memory-isolation-context-sanitization.md) · [Вперёд →](../part-4-output-security/11-output-validation-fact-checking.md)

*Кратко: агент не должен видеть API-ключи и секреты напрямую — брокеринг доступа и хранилища секретов.*

## Суть

> TODO: почему секреты нельзя класть в контекст/память агента.

## Угроза / контекст

> TODO: утечка ключей, токенов, паролей через вывод или логи.

## Подходы и контрмеры

> TODO: secrets manager (Vault и т.п.), брокер доступа, инъекция секретов на уровне инструмента, а не агента.

## Пример (Go)

```go
// TODO: получение секрета через брокер без передачи его в LLM-контекст на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#практические-руководства)

## См. также

- [04 — PII Redaction и Content Filtering](../part-2-input-security/04-pii-redaction-content-filtering.md)
- [06 — RBAC и Tool Permissions](06-rbac-tool-permissions.md)
