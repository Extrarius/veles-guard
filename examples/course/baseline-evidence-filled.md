# Заполненный образец: Agentic Security Baseline (учебный)

[← Оглавление](../../README.md)

> Учебный **Yes** по восьми правилам. Evidence — путь к артефакту или вывод команды, не «см. §08».  
> Пустой шаблон: [templates/agentic-security-baseline.md](../../templates/agentic-security-baseline.md).  
> Воркшоп: [§37](../../notes/part-10-course-appendix/37-agentic-security-baseline-workshop.md).

Статусы: **Yes** · **Partial** · **No** · **N/A**.

| # | Правило | Status | Evidence / notes |
|---|---|---|---|
| 1 | Версии MCP-серверов / skills **pinned** — нет `latest` / floating | Yes | `examples/bash/verify-pins.sh` на корне репо → `OK` (нет `latest` / `*` / `^` / `~` в mcp.json-like файлах) |
| 2 | Перед install — trusted source и/или проверка подписи / provenance | Yes | [baseline-fixtures/trusted-source-review.md](baseline-fixtures/trusted-source-review.md) — блок Good: source + sha256 + owner |
| 3 | Scan / lint **до** установки (описания tools, scripts, manifest) | Yes | [baseline-fixtures/pre-install-lint-notes.md](baseline-fixtures/pre-install-lint-notes.md); сверка с [bad-good-skill-manifest.md](bad-good-skill-manifest.md) |
| 4 | Минимальный `allowed-tools` (least privilege) | Yes | `examples/bash/check-allowed-tools.sh` → `OK`; политика: [templates/course/allowed-tools-policy.md](../../templates/course/allowed-tools-policy.md) |
| 5 | Scripts / MCP запускаются в **non-root sandbox** | Yes | [baseline-fixtures/sandbox-profile.example.md](baseline-fixtures/sandbox-profile.example.md) — user `agent`, FS/net limits |
| 6 | Egress allowlist; исходящая сеть **закрыта по умолчанию** | Yes | [baseline-fixtures/egress-allowlist.example.json](baseline-fixtures/egress-allowlist.example.json) — `default: deny` |
| 7 | Мониторинг filesystem / network / process | Yes | [baseline-fixtures/tool-call-audit-sample.jsonl](baseline-fixtures/tool-call-audit-sample.jsonl) — 3 строки audit (run_id, tool, redacted args) |
| 8 | Inventory endpoint / inventory report (что установлено на endpoint) | Yes | [baseline-fixtures/inventory-endpoint.example.md](baseline-fixtures/inventory-endpoint.example.md) — MCP/skills + owner + pinned version |

## Мета

- **Проект / агент:** `course-workshop-docs-summarizer` (учебный)
- **Owner:** `platform-security@example.com`
- **Дата ревью:** `2026-08-12`
- **Следующий пересмотр:** `2026-11-12`

## Правило Yes

**Yes** только если в Evidence указан путь к файлу (свой или из `examples/course/…`) или конкретный вывод команды. Отсылка «см. §08 / §13» без артефакта — не Evidence.

## См. также

- [baseline-fixtures/](baseline-fixtures/)
- [templates/course/agentic-security-baseline.md](../../templates/course/agentic-security-baseline.md)
