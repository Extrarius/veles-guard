---
tags: [ai-security, шаблон, mcp-review, skills]
статус: шаблон
---

# Шаблон: MCP / Skill Review

[← Оглавление](../README.md)

> Рабочая форма ревью **MCP server** или **agent skill** перед подключением. Не дублирует [mcp-server-review-template.md](mcp-server-review-template.md) — тот глубже по MCP-серверу; этот короче и покрывает skill + общий decision. Контекст: [19 — MCP Security](../notes/part-6-multi-agent-security/19-mcp-security.md), [31 — CI/CD, MCP, Skills](../notes/part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md).

## Identity

- **Name:** `<...>`
- **Type:** `<MCP server / agent skill>`
- **Source:** `<registry / git URL / vendor>`
- **Version / commit / hash:** `<pinned>`
- **Owner:** `<...>`
- **Reviewed by:** `<...>`
- **Date:** `<YYYY-MM-DD>`

## Capabilities

- **Tools:** `<список или N/A>`
- **Resources:** `<...>`
- **Prompts:** `<...>`
- **Filesystem access:** `<нет / read / write / paths>`
- **Network access:** `<нет / allowlist destinations>`
- **Shell / scripts:** `<нет / какие>`

## Risk checks

| Check | Yes / No | Notes |
|---|---|---|
| Uses `latest` / floating version | | |
| Has install scripts | | |
| Has postinstall / prebuild | | |
| Has hidden instructions in descriptions | | |
| Has path traversal risk | | |
| Has egress destinations (list below) | | |
| Requires secrets | | |

**Egress destinations (если есть):** `<list or none>`

## Decision

- **Verdict:** `<Allow / Reject / Sandbox only>`
- **Required restrictions:** `<allowed-tools, egress, sandbox, human approval, …>`
- **Next review date:** `<YYYY-MM-DD>`

## См. также

- [mcp-server-review-template.md](mcp-server-review-template.md) — расширенный review MCP-сервера
- [agentic-security-baseline.md](agentic-security-baseline.md) — минимальный baseline
