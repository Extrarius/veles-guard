---
tags: [ai-security, course-appendix, baseline, mcp, skills, workshop]
часть: "Часть X — Учебное приложение"
статус: готово
обновлено: 2026-08-12
изменения: "Воркшоп: Evidence по образцу examples/course; Yes только с путём к артефакту."
---

# 37 — Agentic Security Baseline Workshop

> Навигация: [Оглавление](../../README.md) · [← Назад](36-mcp-skill-review-workshop.md) · [Вперёд →](38-ai-agent-security-testing-workshop.md)

*Кратко: пройти 8 правил минимального набора безопасности (baseline) для агента / MCP / навыков (skills): открыть заполненный образец, сделать свой набор с путём к артефакту в Evidence, связать с политикой разрешённых инструментов (allowed-tools policy) и проверками в CI.*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-10/37-agentic-security-baseline-workshop.py) ·
> [Bash](../../examples/bash/part-10/37-agentic-security-baseline-workshop.sh) ·
> [TypeScript](../../examples/typescript/part-10/37-agentic-security-baseline-workshop.ts) ·
> [C++](../../examples/cpp/part-10/37-agentic-security-baseline-workshop.cpp) ·
> [Java](../../examples/java/part-10/37-agentic-security-baseline-workshop.java)

## Суть

После проверки (review) одного MCP или навыка (skill) ([§36](36-mcp-skill-review-workshop.md)) нужен **системный минимум** для среды агента — не корпоративный контур «на всех» (enterprise), а то, что должно быть включено до регулярного использования.

Основная (каноническая) заполняемая таблица:

- [templates/agentic-security-baseline.md](../../templates/agentic-security-baseline.md)

Заполненный образец (что писать в Evidence):

- [examples/course/baseline-evidence-filled.md](../../examples/course/baseline-evidence-filled.md)
- мини-артефакты: [examples/course/baseline-fixtures/](../../examples/course/baseline-fixtures/)

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
Проверка (review) в §35 отвечает: «можно ли пускать *этот* MCP или навык (skill)?»

Связь с инцидентом: [templates/course/incident-card-mcp-skill.md](../../templates/course/incident-card-mcp-skill.md), полный процесс — [§23](../part-7-testing-compliance/23-incident-response-recovery.md).

## Подходы и контрмеры

### Восемь правил (статусы: Да / Частично / Нет / Не применимо — Yes / Partial / No / N/A)

**Да (Yes)** только если в Evidence указан путь к файлу (свой или из `examples/course/…`) или конкретный вывод команды. «См. §08» без артефакта — не доказательство (evidence).

| # | Правило | Сделать / артефакт |
|---|---|---|
| 1 | Версии зафиксированы (pinned) — нет `latest` / «плавающих» (floating) | Прогнать [verify-pins.sh](../../examples/bash/verify-pins.sh) или зафиксировать «OK» + путь к скрипту |
| 2 | Доверенный источник (trusted source) и/или подпись / происхождение (provenance) | Свой Identity или [trusted-source-review.md](../../examples/course/baseline-fixtures/trusted-source-review.md) |
| 3 | Сканирование / проверка текста (scan / lint) **до** установки | Свой чеклист или [pre-install-lint-notes.md](../../examples/course/baseline-fixtures/pre-install-lint-notes.md) |
| 4 | Минимальный список разрешённых инструментов (`allowed-tools`) | [check-allowed-tools.sh](../../examples/bash/check-allowed-tools.sh) + [allowed-tools-policy.md](../../templates/course/allowed-tools-policy.md) |
| 5 | Скрипты / MCP — песочница не от root (non-root sandbox) | Свой профиль или [sandbox-profile.example.md](../../examples/course/baseline-fixtures/sandbox-profile.example.md) |
| 6 | Белый список исходящего трафика (egress allowlist); сеть закрыта по умолчанию | Свой json или [egress-allowlist.example.json](../../examples/course/baseline-fixtures/egress-allowlist.example.json) |
| 7 | Наблюдение за файлами / сетью / процессами (мониторинг FS / network / process) | Свой журнал или [tool-call-audit-sample.jsonl](../../examples/course/baseline-fixtures/tool-call-audit-sample.jsonl) |
| 8 | Перечень на рабочей станции / отчёт (inventory endpoint / report) | Свой список или [inventory-endpoint.example.md](../../examples/course/baseline-fixtures/inventory-endpoint.example.md) |

### Связка с CI (трек A — не дублируем)

| Проверка | Артефакт |
|---|---|
| Фиксация версий (pin) / запрет `latest` | [examples/bash/verify-pins.sh](../../examples/bash/verify-pins.sh) |
| Белый список инструментов (allowlist tools) | [examples/bash/check-allowed-tools.sh](../../examples/bash/check-allowed-tools.sh) |
| Пример GitHub Actions | [examples/github-actions/agent-security.example.yml](../../examples/github-actions/agent-security.example.yml) |

Ориентиры экосистемы (не обязательны в репозитории): mcp-scan, promptfoo, сканеры состава ПО вендоров (vendor SCA) — см. [literature.md](../literature.md).

### Сценарий воркшопа (20–25 мин)

1. **5 мин** — открыть [baseline-evidence-filled.md](../../examples/course/baseline-evidence-filled.md); разобрать, что в колонке Evidence (путь к файлу / вывод команды).
2. **5 мин** — скопировать пустой [agentic-security-baseline.md](../../templates/agentic-security-baseline.md) (или обёртку [templates/course/agentic-security-baseline.md](../../templates/course/agentic-security-baseline.md)).
3. **8 мин** — правила 2–3–5–6–7–8: сослаться на fixture в [baseline-fixtures/](../../examples/course/baseline-fixtures/) или сделать свой мини-файл по тому же образцу.
4. **4 мин** — правила 1 и 4: прогнать bash (или зафиксировать «на учебной машине OK» + путь к `verify-pins.sh` / `check-allowed-tools.sh`).
5. **3 мин** — ответственный (Owner) и дата пересмотра; при «Нет (No)» по правилам 5 или 6 — не разрешать (Allow) в боевой среде (prod).

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

Учебный сниппет раздела — [examples/bash/part-10/37-agentic-security-baseline-workshop.sh](../../examples/bash/part-10/37-agentic-security-baseline-workshop.sh). Ops-проверки CI — в `examples/bash/verify-pins.sh` и `check-allowed-tools.sh`; они не подменяют политику организации.

## Чек-лист

- [ ] Заполнены 8 правил минимального набора (baseline): Да / Частично / Нет / Не применимо (Yes / Partial / No / N/A)
- [ ] У каждого Да (Yes) в Evidence есть путь к артефакту (свой или `examples/course/…`)
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

- [33 — Course: AI Security Landscape](33-course-ai-security-landscape.md)
- [34 — Course: Agent Assessment and Defense](34-course-agent-assessment-defense.md)
- [35 — Course Appendix: практикум](35-course-appendix-agentic-security.md)
- [36 — MCP / Skill Review Workshop](36-mcp-skill-review-workshop.md)
- [38 — AI Agent Security Testing Workshop](38-ai-agent-security-testing-workshop.md)
- [06 — RBAC и Tool Permissions](../part-3-processing-security/06-rbac-tool-permissions.md)
- [28 — Permissions, sandbox, approval](../part-9-ai-coding-security/28-coding-agent-permissions-sandbox-approval.md)
- [25 — Security-by-Design чек-лист](../part-8-practice/25-security-by-design-checklist.md)
