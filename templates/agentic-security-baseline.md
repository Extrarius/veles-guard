---
tags: [ai-security, шаблон, baseline, mcp, skills]
статус: шаблон
---

# Шаблон: Agentic Security Baseline

[← Оглавление](../README.md)

> Минимальный baseline перед использованием агента / MCP / skills. Не замена threat model и не enterprise-контур «на всех» — что должно быть включено **минимум**. Контекст: [19 — MCP Security](../notes/part-6-multi-agent-security/19-mcp-security.md), [31 — CI/CD, MCP, Skills](../notes/part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md), [32 — AI Coding Security Checklist](../notes/part-9-ai-coding-security/32-ai-coding-security-checklist.md).

Статусы: **Yes** · **Partial** · **No** · **N/A**.

| # | Правило | Status | Evidence / notes |
|---|---|---|---|
| 1 | Версии MCP-серверов / skills **pinned** — нет `latest` / floating | | |
| 2 | Перед install — trusted source и/или проверка подписи / provenance | | |
| 3 | Scan / lint **до** установки (описания tools, scripts, manifest) | | |
| 4 | Минимальный `allowed-tools` (least privilege) | | |
| 5 | Scripts / MCP запускаются в **non-root sandbox** | | |
| 6 | Egress allowlist; исходящая сеть **закрыта по умолчанию** | | |
| 7 | Мониторинг filesystem / network / process | | |
| 8 | Inventory endpoint / inventory report (что установлено на endpoint) | | |

## Мета

- **Проект / агент:** `<...>`
- **Owner:** `<...>`
- **Дата ревью:** `<YYYY-MM-DD>`
- **Следующий пересмотр:** `<YYYY-MM-DD>`

## См. также

- [mcp-skill-review.md](mcp-skill-review.md) — форма ревью MCP server / agent skill
- [mcp-server-review-template.md](mcp-server-review-template.md) — детальный review MCP-сервера
- Учебные проверки: [examples/bash/verify-pins.sh](../examples/bash/verify-pins.sh), [examples/bash/check-allowed-tools.sh](../examples/bash/check-allowed-tools.sh)
- Пример CI: [examples/github-actions/agent-security.example.yml](../examples/github-actions/agent-security.example.yml)
