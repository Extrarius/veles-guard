---
tags: [ai-security, конспект]
часть: "Часть III — Защита обработки"
статус: черновик
---

# 06 — RBAC и Tool Permissions

> Навигация: [Оглавление](../../README.md) · [← Назад](../part-2-input-security/05-rate-limiting-quotas-token-bombing.md) · [Вперёд →](07-parameter-validation-schema.md)

*Кратко: scoped, just-in-time права для агента и permission gating на каждый вызов инструмента.*

## Суть

> TODO: RBAC для агентов, least privilege, allowlist/denylist инструментов.

## Угроза / контекст

> TODO: privilege escalation, tool misuse, wildcard-доступ.

## Подходы и контрмеры

> TODO: scoped permissions, just-in-time grants, policy-as-code, permission gating перед tool call.

## Пример (Go)

```go
// TODO: декларативная модель прав и проверка перед tool call на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#практические-руководства)

## См. также

- [07 — Parameter Validation и Schema Enforcement](07-parameter-validation-schema.md)
- [10 — Secrets Management](10-secrets-management.md)
