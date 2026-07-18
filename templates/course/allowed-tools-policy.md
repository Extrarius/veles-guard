---
tags: [ai-security, шаблон, course, allowed-tools, policy]
статус: шаблон
---

# Course: политика разрешённых инструментов (Allowed Tools Policy)

[← Оглавление](../../README.md)

> Политика минимальных прав для инструментов (tools) / MCP / навыков (skills). Контекст: [§06 RBAC](../../notes/part-3-processing-security/06-rbac-tool-permissions.md), [§28 Permissions](../../notes/part-9-ai-coding-security/28-coding-agent-permissions-sandbox-approval.md), [§35 Baseline workshop](../../notes/part-10-course-appendix/35-agentic-security-baseline-workshop.md).

## 1. Мета

- **Проект / агент:** `<...>`
- **Ответственный (Owner):** `<...>`
- **Дата:** `<YYYY-MM-DD>`
- **Среда:** `<разработка (dev) / стенд (staging) / боевая (production)>`

## 2. Белый список инструментов (allowlist tools)

| Инструмент / возможность (tool / capability) | Разрешено | Нужно подтверждение (approval) | Запрещено | Примечание |
|---|---|---|---|---|
| `<read_file>` | ☐ | ☐ | ☐ | |
| `<run_terminal>` | ☐ | ☐ | ☐ | |
| `<network_fetch>` | ☐ | ☐ | ☐ | |
| `<mcp:...>` | ☐ | ☐ | ☐ | |

## 3. Запреты по умолчанию

- [ ] Полный доступ / неограниченные инструменты (`danger-full-access` / unrestricted tools) — **запрещены**
- [ ] Оболочка (shell) + сеть (network) одновременно — только через отдельное подтверждение (approval)
- [ ] Секреты (secrets) в аргументах / переменных окружения инструмента (args / env tool) — запрещены или только через хранилище (vault-only)
- [ ] Неизвестный MCP / навык (skill) — запретить, пока не пройдена проверка (deny until review)

## 4. Подтверждение (approval)

- **Кто утверждает опасные инструменты (tools):** `<роль (role)>`
- **Как фиксируется:** `<тикет (ticket) / PR / форма (form)>`
- **Срок пересмотра белого списка (allowlist):** `<YYYY-MM-DD>`

## 5. Решение

- **Политика утверждена:** Да / Нет (Yes / No)
- **Подпись ответственного (Owner):** `<...>`

## См. также

- [mcp-skill-review.md](mcp-skill-review.md)
- [agentic-security-baseline.md](agentic-security-baseline.md)
- [examples/bash/check-allowed-tools.sh](../../examples/bash/check-allowed-tools.sh)
