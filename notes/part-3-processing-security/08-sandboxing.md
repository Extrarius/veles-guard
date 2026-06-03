---
tags: [ai-security, конспект]
часть: "Часть III — Защита обработки"
статус: черновик
---

# 08 — Sandboxing

> Навигация: [Оглавление](../../README.md) · [← Назад](07-parameter-validation-schema.md) · [Вперёд →](09-memory-isolation-context-sanitization.md)

*Кратко: изоляция выполнения кода — container-based (Docker, gVisor) и VM-based (KVM, Microsandbox).*

## Суть

> TODO: уровни изоляции (OS / container / VM), когда что применять.

## Угроза / контекст

> TODO: unexpected code execution (RCE) через сгенерированный код.

## Подходы и контрмеры

> TODO: Docker hardening, gVisor, Firecracker, Kata, E2B/Daytona; ограничение filesystem/network/capabilities.

## Пример (Go)

```go
// TODO: запуск недоверенного кода в изолированном контейнере из Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#инструменты)

## См. также

- [13 — Egress Control и Data Exfiltration](../part-4-output-security/13-egress-control-data-exfiltration.md)
- [07 — Parameter Validation и Schema Enforcement](07-parameter-validation-schema.md)
