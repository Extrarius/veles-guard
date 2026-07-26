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
- **Agent identity (если production):** `<dedicated principal — не shared SA/API key across agents>`
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
| Would share credentials with other agents | | |

**Egress destinations (если есть):** `<list or none>`

## Decision

- **Verdict:** `<Allow / Reject / Sandbox only>`
- **Required restrictions:** `<allowed-tools, egress, sandbox, human approval, dedicated agent identity, …>`
- **Next review date:** `<YYYY-MM-DD>`

## Re-review triggers

`pin + hash` без re-review по событию **не** закрывает rug pull (подмену после одобрения). Auto-apply обновлений запрещён, пока нет нового **Allow** по этой же форме (Identity → Capabilities → Risk checks → Decision). До Allow остаётся pin на предыдущей одобренной версии.

| Событие | Действие |
|---|---|
| version / commit / hash изменился | block auto-apply → full re-review |
| drift: tools / description / scripts / permissions / resources | alert + re-review |
| смена source / owner / registry | re-review |
| обнаружен `latest` / unpin | deny until pin + review |
| наступила Next review date | scheduled re-review |

## См. также

- [mcp-server-review-template.md](mcp-server-review-template.md) — расширенный review MCP-сервера
- [agentic-security-baseline.md](agentic-security-baseline.md) — минимальный baseline
- [06 — RBAC / Agent Identity](../notes/part-3-processing-security/06-rbac-tool-permissions.md#agent-identity-и-safe-tool-binding)
- [19 — MCP Security](../notes/part-6-multi-agent-security/19-mcp-security.md) — metadata drift / Runtime Trust Gap
- [31 — CI/CD, MCP, Skills](../notes/part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md) — diff review / rug pull

