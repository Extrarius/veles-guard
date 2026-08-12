---
tags: [ai-security, шаблон, baseline, mcp, skills]
статус: шаблон
---

# Шаблон: Agentic Security Baseline

[← Оглавление](../README.md)

> Минимальный baseline перед использованием агента / MCP / skills. Не замена threat model и не enterprise-контур «на всех» — что должно быть включено **минимум**. Контекст: [19 — MCP Security](../notes/part-6-multi-agent-security/19-mcp-security.md), [31 — CI/CD, MCP, Skills](../notes/part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md), [32 — AI Coding Security Checklist](../notes/part-9-ai-coding-security/32-ai-coding-security-checklist.md).

Статусы: **Yes** · **Partial** · **No** · **N/A**.

**Yes** только если в Evidence указан путь к артефакту (свой или из [`examples/course/`](../examples/course/)). Отсылка «см. §08 / §13» без файла — не Evidence. Заполненный образец: [baseline-evidence-filled.md](../examples/course/baseline-evidence-filled.md).

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

## Accepted evidence

Тип доказательства по правилу. Практика — файлы в [`examples/course/baseline-fixtures/`](../examples/course/baseline-fixtures/), не чтение частей I–IX.

| # | Тип доказательства | Учебный артефакт |
|---|---|---|
| 1 | Вывод `verify-pins.sh` (OK) или lockfile / mcp.json без `latest` | [examples/bash/verify-pins.sh](../examples/bash/verify-pins.sh) |
| 2 | Identity: source + hash + owner | [trusted-source-review.md](../examples/course/baseline-fixtures/trusted-source-review.md) |
| 3 | Чеклист scan/lint до install | [pre-install-lint-notes.md](../examples/course/baseline-fixtures/pre-install-lint-notes.md) |
| 4 | Вывод `check-allowed-tools.sh` (OK) + политика без `*` | [examples/bash/check-allowed-tools.sh](../examples/bash/check-allowed-tools.sh) |
| 5 | Профиль non-root + FS/net limits | [sandbox-profile.example.md](../examples/course/baseline-fixtures/sandbox-profile.example.md) |
| 6 | Default deny + список destinations | [egress-allowlist.example.json](../examples/course/baseline-fixtures/egress-allowlist.example.json) |
| 7 | Журнал tool calls (run_id, tool, redacted args) | [tool-call-audit-sample.jsonl](../examples/course/baseline-fixtures/tool-call-audit-sample.jsonl) |
| 8 | Таблица MCP/skills + owner + pinned version | [inventory-endpoint.example.md](../examples/course/baseline-fixtures/inventory-endpoint.example.md) |

## Мета

- **Проект / агент:** `<...>`
- **Owner:** `<...>`
- **Дата ревью:** `<YYYY-MM-DD>`
- **Следующий пересмотр:** `<YYYY-MM-DD>`

## См. также

- [agent-passport.md](agent-passport.md) — спецификация агента до запуска (класс риска R0–R3, owner)
- [mcp-skill-review.md](mcp-skill-review.md) — форма ревью MCP server / agent skill
- [mcp-server-review-template.md](mcp-server-review-template.md) — детальный review MCP-сервера
- Учебные проверки: [examples/bash/verify-pins.sh](../examples/bash/verify-pins.sh), [examples/bash/check-allowed-tools.sh](../examples/bash/check-allowed-tools.sh)
- Заполненный образец Evidence: [examples/course/baseline-evidence-filled.md](../examples/course/baseline-evidence-filled.md)
- Пример CI: [examples/github-actions/agent-security.example.yml](../examples/github-actions/agent-security.example.yml)
