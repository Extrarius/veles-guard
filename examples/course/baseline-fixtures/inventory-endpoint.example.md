# Правило 8: inventory endpoint (учебный)

[← Оглавление](../../../README.md) · [filled sample](../baseline-evidence-filled.md)

> Что установлено на учебной «рабочей станции» воркшопа. Owner обязателен.

| Компонент | Тип | Version (pinned) | Source / hash | Owner |
|---|---|---|---|---|
| `docs-summarizer` | skill | `1.2.0` | `git+https://github.example/org/docs-summarizer@v1.2.0` / `sha256:aaa…aaa` | `platform-security@example.com` |
| `repo_search` | MCP tool (read-only) | `0.4.1` | internal registry `@0.4.1` / `sha256:bbbb…bbbb` | `platform-security@example.com` |
| `audit-ingest` | sidecar | `2.0.0` | `audit.internal.example` image digest `sha256:cccc…cccc` | `sre-oncall@example.com` |

Нет `latest`. Нет owner=`unknown`. Следующий пересмотр: `2026-11-12` (как в filled sample).
