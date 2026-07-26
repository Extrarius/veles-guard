---
tags: [ai-security, course-appendix, mcp, skills, workshop]
часть: "Часть X — Учебное приложение"
статус: готово
обновлено: 2026-07-18
изменения: "Практический набор и навигация: §36 Testing Workshop + guides/."
---

# 33 — Course Appendix: практикум по безопасности AI-агентов, MCP и Skills

> Навигация: [Оглавление](../../README.md) · [← Назад](../part-9-ai-coding-security/32-ai-coding-security-checklist.md) · [Вперёд →](34-mcp-skill-review-workshop.md)

*Кратко: прикладное приложение после теории — шаблоны проверки (review), минимальные правила безопасности (baseline), политика разрешённых инструментов (allowed-tools policy) и безопасные учебные примеры для MCP, навыков агента (agent skills) и работы с AI в коде (AI-coding workflow).*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-10/33-course-appendix-agentic-security.py) ·
> [Bash](../../examples/bash/part-10/33-course-appendix-agentic-security.sh) ·
> [TypeScript](../../examples/typescript/part-10/33-course-appendix-agentic-security.ts) ·
> [C++](../../examples/cpp/part-10/33-course-appendix-agentic-security.cpp) ·
> [Java](../../examples/java/part-10/33-course-appendix-agentic-security.java)

## Суть

Фокус раздела — перевести риски MCP, навыков агента (agent skills) и работы с AI в коде (AI-coding workflow) в конкретные действия:

- что проверить перед подключением MCP или навыка (skill);
- что ограничить через список разрешённых инструментов (`allowed-tools`), песочницу (sandbox) и контроль исходящего трафика (egress);
- что запретить по умолчанию: «плавающую» версию (`latest`), любые инструменты без ограничений (wildcard tools), скрытые инструкции;
- что вынести на ручное подтверждение человеком (human approval);
- что писать в журналы (логировать) и как зафиксировать ответственного (owner) и перечень установленных компонентов (inventory).

Иными словами, это прикладной набор после теории: шаблон проверки (review template), минимальные правила (baseline), политика инструментов (allowed-tools policy), карточка инцидента (incident card) и безопасные учебные примеры «плохо / хорошо» (bad / good).

## Для кого

| Роль | Как использовать |
|---|---|
| Преподаватель | Практические материалы к лекции / воркшоп 30 мин |
| Студент | Чек-лист самостоятельной проверки агента |
| Разработчик | Минимальная проверка безопасности (security review) перед подключением MCP и навыков (skills) |
| Команда | Основа внутреннего согласования (approval) и минимальных правил (baseline) |

## Что НЕ является целью

Раздел **не** предназначен для:

- публикации рабочих вредоносных нагрузок (offensive payloads);
- обхода защит;
- демонстрации взлома реальных MCP и навыков (skills).

Все примеры — учебные: найти риск, ограничить его и не допустить повторения. Это совпадает с позицией репозитория в [README](../../README.md): не публиковать реальные секреты, внутренние URL или вредоносные нагрузки (offensive payload).

## Угроза / контекст

Агент — недоверенный исполнитель с правами. Границы доверия (trust boundaries) шире, чем «запрос пользователя (prompt)»:

```text
запрос (prompt)
  → описание инструмента (tool description)
  → сервер MCP (MCP server)
  → навык / плагин (skill / plugin)
  → инструкции в репозитории (repo instructions)
  → конвейер сборки и выката (CI/CD)
```

Типичные сбои процесса (не «магия модели»):

- установка с «плавающей» версией (`latest`) / без фиксации версии (pin) и происхождения пакета (provenance);
- скрытые инструкции в описаниях (descriptions);
- слишком широкий список разрешённых инструментов (`allowed-tools`);
- исходящий трафик (egress) и песочница (sandbox) «как получится»;
- нет ответственного (owner), перечня установленных компонентов (inventory) и обязательной проверки перед подключением (review gate).

Теория и модель угроз (threat model): [§19 MCP](../part-6-multi-agent-security/19-mcp-security.md), [§27 Repo instructions](../part-9-ai-coding-security/27-repository-instructions-attack-surface.md), [§31 CI/CD · MCP · Skills](../part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md), [§32 Checklist](../part-9-ai-coding-security/32-ai-coding-security-checklist.md).

## Практический набор

| # | Артефакт | Путь |
|---|---|---|
| 1 | Проверка MCP / навыка (MCP / Skill Review), воркшоп | [templates/course/mcp-skill-review.md](../../templates/course/mcp-skill-review.md) → [templates/mcp-skill-review.md](../../templates/mcp-skill-review.md) |
| 2 | Минимальные правила безопасности агента (Agentic Security Baseline), воркшоп | [templates/course/agentic-security-baseline.md](../../templates/course/agentic-security-baseline.md) → [templates/agentic-security-baseline.md](../../templates/agentic-security-baseline.md) |
| 3 | Политика разрешённых инструментов (Allowed Tools Policy) | [templates/course/allowed-tools-policy.md](../../templates/course/allowed-tools-policy.md) |
| 4 | Проверки в CI: фиксация версий (pin) и белый список (allowlist) | [examples/github-actions/agent-security.example.yml](../../examples/github-actions/agent-security.example.yml), [examples/bash/](../../examples/bash/) |
| 5 | Карточка инцидента (Incident Card): MCP / навык (Skill) | [templates/course/incident-card-mcp-skill.md](../../templates/course/incident-card-mcp-skill.md) |
| 6 | Учебные «плохо / хорошо» (bad vs good) | [examples/course/](../../examples/course/) |
| 7 | Воркшоп проверки (review) | [§34](34-mcp-skill-review-workshop.md) |
| 8 | Воркшоп минимальных правил (baseline) | [§35](35-agentic-security-baseline-workshop.md) |
| 9 | Гайд проверки агента + воркшоп findings | [guides/ai-agent-security-testing-guide.md](../../guides/ai-agent-security-testing-guide.md) → [§36](36-ai-agent-security-testing-workshop.md) |

## План воркшопа (outline), 30 мин

| Мин | Тема | Что сделать |
|---|---|---|
| 0–3 | Агент = исполнитель с правами | Одна фраза: минимальные права (least privilege), подтверждение человеком (approval), журналирование (logging) |
| 3–8 | Границы доверия (trust boundaries) | Пройти цепочку: запрос (prompt) → описание инструмента → MCP → навык (skill) → репозиторий → CI |
| 8–14 | Цепочка поставок (supply chain) | `latest`, скрипты установки (install scripts), фиксация версии (pin) + хеш (hash); смотреть «плохой» навык (Bad skill) |
| 14–20 | Среда выполнения (runtime) | разрешённые инструменты (allowed-tools), песочница (sandbox), исходящий трафик (egress), не от root (non-root), секреты (secrets) |
| 20–25 | CI и перечень компонентов (inventory) | Пример workflow + bash; ориентиры: mcp-scan, promptfoo, сканеры вендоров (не обязательны) |
| 25–30 | Один набор минимальных правил (baseline) | Заполнить 8 правил из [agentic-security-baseline.md](../../templates/agentic-security-baseline.md) |

Дальше — углубление в [§34](34-mcp-skill-review-workshop.md), [§35](35-agentic-security-baseline-workshop.md) и [§36](36-ai-agent-security-testing-workshop.md).

## Подходы и контрмеры

1. **Проверка до установки (review before install)** — форма проверки MCP/навыка (MCP/Skill review), не «поставили и потом посмотрели».
2. **Фиксировать всё (pin everything)** — версии и хеш (hash); запрет «плавающих» версий (floating / `latest`) в финальных конфигах.
3. **Минимальные права на инструменты (least privilege tools)** — явный белый список (allowlist), без `*`.
4. **Изоляция при запуске (runtime isolation)** — песочница не от root (non-root sandbox), исходящий трафик закрыт по умолчанию (egress deny-by-default).
5. **CI как шлюз (CI as gate)** — проверка фиксации версий (pin) и списка инструментов (allowed-tools) до слияния (merge).
6. **Ответственный + перечень (owner + inventory)** — кто отвечает и что установлено.
7. **Карточка инцидента (incident card)** — короткий путь: аварийное отключение (kill-switch) → отзыв доступа (revoke) → полный отчёт ([§23](../part-7-testing-compliance/23-incident-response-recovery.md)).

## Пример (Go)

Иллюстрация идеи «запрещено, пока явно не разрешено» (deny by default) для имени инструмента (tool) — не полноценная среда выполнения (runtime):

```go
package tools

import "fmt"

var allowed = map[string]bool{
	"read_file":   true,
	"repo_search": true,
}

func Authorize(tool string) error {
	if !allowed[tool] {
		return fmt.Errorf("tool %q not in allowlist", tool)
	}
	return nil
}
```

Полный контур прав — в [§06](../part-3-processing-security/06-rbac-tool-permissions.md) и [§28](../part-9-ai-coding-security/28-coding-agent-permissions-sandbox-approval.md).

## Чек-лист

- [ ] Понятна аудитория и границы («не руководство по атакам» / не offensive manual)
- [ ] Есть ссылки на `templates/course` и рабочие артефакты: минимальные правила (baseline), проверка (review), CI, bash
- [ ] План воркшопа (outline) на 30 мин можно провести без внешних слайдов
- [ ] Примеры «плохо / хорошо» (bad/good) открыты из `examples/course/`
- [ ] Следующий шаг — §34 (review), §35 (baseline) или §36 (testing / findings)

## Литература

- [Список литературы](../literature.md) — в т.ч. блок про навыки агента и сканирование MCP (Agent skills / MCP scanning tools)
- [MCP Specification](https://modelcontextprotocol.io/) (официальная спецификация)
- OWASP LLM Top 10 / LLM applications — см. сопоставление (mapping) в [literature.md](../literature.md)

## См. также

- [34 — MCP / Skill Review Workshop](34-mcp-skill-review-workshop.md)
- [35 — Agentic Security Baseline Workshop](35-agentic-security-baseline-workshop.md)
- [36 — AI Agent Security Testing Workshop](36-ai-agent-security-testing-workshop.md)
- [AI Agent Security Testing Guide](../../guides/ai-agent-security-testing-guide.md)
- [19 — MCP Security](../part-6-multi-agent-security/19-mcp-security.md)
- [31 — CI/CD, MCP, Skills](../part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md)
- [32 — AI Coding Security Checklist](../part-9-ai-coding-security/32-ai-coding-security-checklist.md)
