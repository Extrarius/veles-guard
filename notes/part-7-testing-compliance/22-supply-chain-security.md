---
tags: [ai-security, конспект]
часть: "Часть VII — Тестирование и compliance"
статус: черновик
---

# 22 — Supply Chain Security

> Навигация: [Оглавление](../../README.md) · [← Назад](21-compliance-standards.md) · [Вперёд →](23-incident-response-recovery.md)

*Кратко: проверка зависимостей, моделей, MCP-серверов, prompts и skills; отравленные RAG-данные.*

## Суть

> TODO: что входит в supply chain агента и зачем её проверять.

## Угроза / контекст

> TODO: model poisoning, backdoors, отравлённые датасеты/зависимости, вредные MCP-серверы.

## Подходы и контрмеры

> TODO: ModelScan, NB Defense, Semgrep AI rules, Snyk, secret scanning, agent inventory.

## Пример (Go)

```go
// TODO: проверка целостности артефактов/зависимостей агента на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#стандарты-и-фреймворки)

## См. также

- [19 — MCP Security](../part-6-multi-agent-security/19-mcp-security.md)
- [09 — Memory Isolation и Context Sanitization](../part-3-processing-security/09-memory-isolation-context-sanitization.md)
