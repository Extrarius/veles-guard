---
tags: [ai-security, course-appendix, baseline, mcp, skills, workshop]
часть: "Часть X — Учебное приложение"
статус: готово
обновлено: 2026-07-18
изменения: "Навигация «Вперёд» → §36 (AI Agent Security Testing Workshop)."
---

# 35 — Agentic Security Baseline Workshop

> Навигация: [Оглавление](../../README.md) · [← Назад](34-mcp-skill-review-workshop.md) · [Вперёд →](36-ai-agent-security-testing-workshop.md)

*Кратко: пройти 8 правил минимального набора безопасности (baseline) для агента / MCP / навыков (skills), связать с политикой разрешённых инструментов (allowed-tools policy), проверками в CI и bash, зафиксировать ответственного (Owner).*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-10/35-agentic-security-baseline-workshop.py) ·
> [Bash](../../examples/bash/part-10/35-agentic-security-baseline-workshop.sh) ·
> [TypeScript](../../examples/typescript/part-10/35-agentic-security-baseline-workshop.ts) ·
> [C++](../../examples/cpp/part-10/35-agentic-security-baseline-workshop.cpp) ·
> [Java](../../examples/java/part-10/35-agentic-security-baseline-workshop.java)

## Суть

После проверки (review) одного MCP или навыка (skill) ([§34](34-mcp-skill-review-workshop.md)) нужен **системный минимум** для среды агента — не корпоративный контур «на всех» (enterprise), а то, что должно быть включено до регулярного использования.

Основная (каноническая) заполняемая таблица:

- [templates/agentic-security-baseline.md](../../templates/agentic-security-baseline.md)

Обёртка для воркшопа:

- [templates/course/agentic-security-baseline.md](../../templates/course/agentic-security-baseline.md)

Политика инструментов (tools):

- [templates/course/allowed-tools-policy.md](../../templates/course/allowed-tools-policy.md)

## Угроза / контекст

Без минимальных правил (baseline) типичный провал:

```text
удобный MCP
  → «плавающая» версия (latest)
  → слишком широкие инструменты (tools)
  → открытый исходящий трафик (egress)
  → нет перечня установленных компонентов (inventory)
  → инцидент
```

Минимальные правила (baseline) отвечают на вопрос: «можно ли вообще пускать агента в эту среду?»  
Проверка (review) в §34 отвечает: «можно ли пускать *этот* MCP или навык (skill)?»

Связь с инцидентом: [templates/course/incident-card-mcp-skill.md](../../templates/course/incident-card-mcp-skill.md), полный процесс — [§23](../part-7-testing-compliance/23-incident-response-recovery.md).

## Подходы и контрмеры

### Восемь правил (статусы: Да / Частично / Нет / Не применимо — Yes / Partial / No / N/A)

| # | Правило | На воркшопе проверить |
|---|---|---|
| 1 | Версии зафиксированы (pinned) — нет `latest` / «плавающих» (floating) | Конфиг агента, файл блокировок (lockfile), список MCP |
| 2 | Доверенный источник (trusted source) и/или подпись / происхождение (provenance) | Откуда ставите; есть ли хеш (hash) |
| 3 | Сканирование / проверка текста (scan / lint) **до** установки | Описания (descriptions), скрипты (scripts), манифест (manifest) |
| 4 | Минимальный список разрешённых инструментов (`allowed-tools`) | Заполнить [allowed-tools-policy.md](../../templates/course/allowed-tools-policy.md) |
| 5 | Скрипты / MCP — песочница не от root (non-root sandbox) | Как запускается процесс |
| 6 | Белый список исходящего трафика (egress allowlist); сеть закрыта по умолчанию | Куда агент может ходить |
| 7 | Наблюдение за файлами / сетью / процессами (мониторинг FS / network / process) | Хотя бы журналирование вызовов инструментов (tools) |
| 8 | Перечень на рабочей станции / отчёт (inventory endpoint / report) | Список установленных MCP и навыков (skills) + ответственный (Owner) |

### Связка с CI (трек A — не дублируем)

| Проверка | Артефакт |
|---|---|
| Фиксация версий (pin) / запрет `latest` | [examples/bash/verify-pins.sh](../../examples/bash/verify-pins.sh) |
| Белый список инструментов (allowlist tools) | [examples/bash/check-allowed-tools.sh](../../examples/bash/check-allowed-tools.sh) |
| Пример GitHub Actions | [examples/github-actions/agent-security.example.yml](../../examples/github-actions/agent-security.example.yml) |

Ориентиры экосистемы (не обязательны в репозитории): mcp-scan, promptfoo, сканеры состава ПО вендоров (vendor SCA) — см. [literature.md](../literature.md).

### Сценарий воркшопа (20 мин)

1. **5 мин** — открыть минимальные правила (baseline), отметить статус (Status) по своему проекту (или учебному кейсу).
2. **5 мин** — заполнить политику разрешённых инструментов (Allowed Tools Policy) — хотя бы 3–5 инструментов (tools).
3. **5 мин** — прогнать мысль «что упадёт в CI»: фиксация версий (pin) + белый список (allowlist).
4. **5 мин** — назначить ответственного (Owner), дату пересмотра; при «Нет (No)» по критичным правилам — не разрешать (Allow) в боевой среде (prod).

## Пример (Go): запрет «плавающей» версии (floating version)

```go
package pin

import (
	"fmt"
	"strings"
)

func RejectFloating(version string) error {
	v := strings.TrimSpace(strings.ToLower(version))
	if v == "" || v == "latest" || v == "*" || strings.HasPrefix(v, "^") || strings.HasPrefix(v, "~") {
		return fmt.Errorf("floating or empty version %q — pin exact version", version)
	}
	return nil
}
```

Учебный сниппет раздела — [examples/bash/part-10/35-agentic-security-baseline-workshop.sh](../../examples/bash/part-10/35-agentic-security-baseline-workshop.sh). Ops-проверки CI — в `examples/bash/verify-pins.sh` и `check-allowed-tools.sh`; они не подменяют политику организации.

## Чек-лист

- [ ] Заполнены 8 правил минимального набора (baseline): Да / Частично / Нет / Не применимо (Yes / Partial / No / N/A)
- [ ] Есть ответственный (Owner) и дата следующего пересмотра
- [ ] Политика разрешённых инструментов (allowed-tools policy) согласована (нет «любых» / wildcard)
- [ ] Известно, как в CI ловятся фиксация версий (pin) и белый список (allowlist)
- [ ] Для «Частично / Нет» (Partial / No) по правилам 1, 4, 5, 6 — план компенсации или запрет боевой среды (prod)
- [ ] Карточка инцидента (incident card) под рукой на случай компрометации MCP / навыка (skill)

## Литература

- [Список литературы](../literature.md)
- [MCP Specification](https://modelcontextprotocol.io/)
- Конспект: [§08 Sandboxing](../part-3-processing-security/08-sandboxing.md), [§13 Egress](../part-4-output-security/13-egress-control-data-exfiltration.md), [§31](../part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md), [§32](../part-9-ai-coding-security/32-ai-coding-security-checklist.md)

## См. также

- [33 — Course Appendix](33-course-appendix-agentic-security.md)
- [34 — MCP / Skill Review Workshop](34-mcp-skill-review-workshop.md)
- [36 — AI Agent Security Testing Workshop](36-ai-agent-security-testing-workshop.md)
- [06 — RBAC и Tool Permissions](../part-3-processing-security/06-rbac-tool-permissions.md)
- [28 — Permissions, sandbox, approval](../part-9-ai-coding-security/28-coding-agent-permissions-sandbox-approval.md)
- [25 — Security-by-Design чек-лист](../part-8-practice/25-security-by-design-checklist.md)
