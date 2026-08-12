# Правило 3: scan / lint до install (учебный)

[← Оглавление](../../../README.md) · [filled sample](../baseline-evidence-filled.md)

> Чеклист по манифесту / tool description **до** установки. Опора: [bad-good-skill-manifest.md](../bad-good-skill-manifest.md), [bad-good-mcp-tool-description.md](../bad-good-mcp-tool-description.md).

Учебный объект: Good-манифест `docs-summarizer` v1.2.0.

| Проверка | Результат | Заметка |
|---|---|---|
| Нет `latest` / `*` / `^` / `~` в version | Pass | `1.2.0` |
| Есть source + hash + owner | Pass | см. [trusted-source-review.md](trusted-source-review.md) |
| Нет `postinstall` / `curl \| bash` | Pass | только `verify-hash`, `unpack-readonly` |
| Tools — явный список, не `*` | Pass | `read_file` |
| Network default deny | Pass | `network: false` |
| FS не `/` | Pass | `./docs/**`; deny `.env`, secrets, `.git/config` |
| Description без скрытых инструкций | Pass | нет «ignore policy» / exfil |
| Tool description без SYSTEM OVERRIDE | Pass | сверка с good-блоком MCP tool |

Вердикт: **lint OK — можно ставить в sandbox**. Bad-манифест из `bad-good-skill-manifest.md` на этом чеклисте даёт Fail по всем строкам кроме (возможно) имени — **не ставить**.
