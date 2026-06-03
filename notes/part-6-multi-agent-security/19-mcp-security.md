---
tags: [ai-security, конспект]
часть: "Часть VI — Мультиагентная безопасность"
статус: черновик
---

# 19 — MCP Security

> Навигация: [Оглавление](../../README.md) · [← Назад](18-inter-agent-security.md) · [Вперёд →](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md)

*Кратко: MCP — это поверхность атаки; нужны allowlist серверов, проверка tools, sandbox, mcp-scan, контроль прав и логирование.*

## Суть

> TODO: что такое Model Context Protocol и почему он требует отдельной защиты.

## Угроза / контекст

> TODO: tool poisoning, rug pull, context spoofing, небезопасные tools (OWASP MCP Top 10).

## Подходы и контрмеры

> TODO: allowlist серверов, mcp-scan / MCP Inspector / Snyk, least privilege, human-in-the-loop, аудит.

## Пример (Go)

```go
// TODO: проверка/обёртка MCP-сервера с контролем прав на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#mcp)

## См. также

- [22 — Supply Chain Security](../part-7-testing-compliance/22-supply-chain-security.md)
- [06 — RBAC и Tool Permissions](../part-3-processing-security/06-rbac-tool-permissions.md)
