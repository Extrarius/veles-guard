# Правило 5: non-root sandbox profile (учебный)

[← Оглавление](../../../README.md) · [filled sample](../baseline-evidence-filled.md)

> Учебный профиль изоляции. Не конфиг Firecracker/gVisor и не production runtime.

## Профиль `course-docs-summarizer`

| Контроль | Значение |
|---|---|
| User | `agent` (uid ≥ 1000), **не** root |
| Capabilities | drop `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE` |
| Filesystem | read-only root; writable только `/tmp/agent-work` |
| Allow paths | `./docs/**` (как в Good-манифесте) |
| Deny paths | `.env`, `**/*secret*`, `**/.git/config`, `/home`, `/root` |
| Network | off в sandbox; исходящие — только через [egress-allowlist.example.json](egress-allowlist.example.json) на хосте-прокси |
| Process | no new privileges; no docker.sock; no privileged |

Запуск (схема, не команда для копирования в прод): процесс MCP/skill стартует от `agent`, рабочий каталог — workspace курса, секреты в env не монтируются.

Вердикт для воркшопа: **Yes** по правилу 5, если такой профиль (или свой аналог) лежит рядом с baseline и процесс реально не root.
