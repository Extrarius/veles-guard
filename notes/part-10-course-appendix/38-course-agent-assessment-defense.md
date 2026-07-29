---
tags: [ai-security, course-appendix, assessment, defense, workshop]
часть: "Часть X — Учебное приложение"
статус: готово
обновлено: 2026-07-29
изменения: "Учебный assessment and defense: матрица классов → §§ I–IX; hard/soft guardrails."
---

# 38 — Course: Agent Assessment and Defense

> Навигация: [Оглавление](../../README.md) · [← Назад](37-ai-agent-security-testing-workshop.md) · [Вперёд →](../../README.md)

*Кратко: учебная карта «что оценивать у агента и чем закрывать» — input / output / RAG / MCP / red team — со ссылками на части I–IX. Без offensive payloads и без вендорного стека.*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-10/38-course-agent-assessment-defense.py) ·
> [Bash](../../examples/bash/part-10/38-course-agent-assessment-defense.sh) ·
> [TypeScript](../../examples/typescript/part-10/38-course-agent-assessment-defense.ts) ·
> [C++](../../examples/cpp/part-10/38-course-agent-assessment-defense.cpp) ·
> [Java](../../examples/java/part-10/38-course-agent-assessment-defense.java)

## Суть

Агент — не «чат с моделью», а связка:

```text
вход (user / docs / tools output)
  → модель + политика
  → выход (текст / HTML / действия)
  → tools / MCP / RAG / внешние системы
```

**Assessment** — понять, какие классы угроз релевантны *вашему* агенту и где их ловить (до релиза и в runtime).  
**Defense** — внешние контроли (policy, schema, sandbox, egress, HITL, monitoring), а не «надежда на alignment».

Этот раздел — **навигатор** к канону частей I–IX и к практикуму (§33–37). Не замена threat model ([§02](../part-1-architecture-threats/02-threat-model.md)) и не offensive manual.

## Для кого

| Роль | Как использовать |
|---|---|
| Преподаватель | 20–40 мин перед / после практикума: классы угроз → §§ |
| Студент | Чек-лист «что проверить у учебного агента» |
| Разработчик | Быстрый маршрут finding → раздел конспекта |
| Команда | Общий язык assessment areas |

## Что НЕ является целью

- Публикация jailbreak-промптов, вредоносных рецептов или XSS payloads.
- Новый security framework вместо OWASP / NIST / ATLAS.
- Каталог коммерческих gateway / red-team продуктов.
- Дублирование полного [§20](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md) или [Testing Guide](../../guides/ai-agent-security-testing-guide.md).

## Угроза / контекст

Типичный разрыв: есть агент с tools и RAG, а assessment сводится к «потрогали chat». Нужна матрица по **поверхностям**.

## Матрица assessment → части I–IX

| Область | Что оценивать (безопасно) | Канон |
|---|---|---|
| **Input** | Direct / indirect prompt injection; обход инструкций через роли | [§03](../part-2-input-security/03-prompt-injection-detection.md) |
| **Output** | Небезопасный вывод (разметка, скрипты, утечки) до рендера / доверия UI | [§11](../part-4-output-security/11-output-validation-fact-checking.md), [§04](../part-2-input-security/04-pii-redaction-content-filtering.md) |
| **Knowledge / RAG** | Отравление документов в базе; retrieval вне ACL; exfil через ответ | [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md), [§13](../part-4-output-security/13-egress-control-data-exfiltration.md) |
| **Tools / MCP** | Вредоносный / отравленный tool; **confused deputy** (агент действует с чужими правами по подсказке) | [§19](../part-6-multi-agent-security/19-mcp-security.md), [§06](../part-3-processing-security/06-rbac-tool-permissions.md) |
| **Assurance** | Red team / evals до релиза; LLM-as-judge только как доп. слой | [§20](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md), [Testing Guide](../../guides/ai-agent-security-testing-guide.md), [§37](37-ai-agent-security-testing-workshop.md) |

Карта «тема × стандарт»: [notes/mapping.md](../mapping.md).

### Мини-сценарии (учебные, без payloads)

1. **Indirect injection через документ** — в knowledge base попадает текст с инструкциями для модели → проверить access-aware retrieval и изоляцию контекста (§09).
2. **Insecure output** — модель возвращает разметку, опасную при render в UI → sanitize / CSP / не доверять raw HTML (§11).
3. **Confused deputy** — сообщение (например, email) маскируется под «системное» и толкает агента вызвать привилегированный tool от имени пользователя → least privilege + confirmation (§19, §06, §14).
4. **Malicious MCP** — description/schema скрывает побочный эффект → review до install (§35, §19).

## Guardrails: hard block vs soft response

Внешний safety-слой (classifier / policy) ≠ «модель сама откажется».

| Режим | Поведение | Зачем |
|---|---|---|
| **Hard block** | Запрос/ответ отсекается классификатором; дальше пайплайн не идёт (или только безопасный stub) | Не дать вредоносному вводу/выводу дойти до tools / UI |
| **Soft response** | После hard block пользователь получает **вежливый отказ** без раскрытия внутренней причины фильтра и без «system notification» в ответе | UX; не обучать атакующего точной логике блокировки |

Классификаторы (ориентир): moderation APIs, Llama Guard и аналоги — см. [literature.md](../literature.md) (Moderation / classifiers). Канон детекции на входе — [§03](../part-2-input-security/03-prompt-injection-detection.md); фильтрация контента — [§04](../part-2-input-security/04-pii-redaction-content-filtering.md).

> **Правило:** hard block — решение политики; soft response — представление пользователю. Не подменять hard block «надеждой, что модель сама откажется».

## Red team assessment

До релиза: matrix → Expected (контроль срабатывает) → findings → regression ([§37](37-ai-agent-security-testing-workshop.md), [Testing Guide](../../guides/ai-agent-security-testing-guide.md)).

**LLM-as-a-Judge** в suite: отдельная модель/промпт оценивает пару (запрос, ответ / tool trace) на нарушение политики — только **дополнительный** слой (EV-03 в [§20](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md)), не единственная защита. Детерминированные checks и human review для high-risk обязательны.

## Подходы и контрмеры

1. Составить матрицу областей (таблица выше) под *свой* агент — вычеркнуть N/A.
2. На каждую High-область — Expected control и раздел канона.
3. Guardrails: hard + soft раздельно; не светить внутреннюю причину block.
4. MCP/tools: review до connect; confused deputy в threat model.
5. Перейти к практикуму: [§33](33-course-ai-security-landscape.md) → [§34](34-course-appendix-agentic-security.md) → [§35](35-mcp-skill-review-workshop.md) → [§36](36-agentic-security-baseline-workshop.md) → [§37](37-ai-agent-security-testing-workshop.md).

## Пример (Go): область assessment → якоря конспекта

```go
package assessment

import "fmt"

// Area — учебная область assessment агента (не compliance-код).
type Area string

const (
	AreaInput     Area = "input"
	AreaOutput    Area = "output"
	AreaKnowledge Area = "knowledge"
	AreaToolsMCP  Area = "tools_mcp"
	AreaAssurance Area = "assurance"
)

// HandbookRefs — короткие якоря вида "§03".
func HandbookRefs(area Area) ([]string, error) {
	switch area {
	case AreaInput:
		return []string{"§03"}, nil
	case AreaOutput:
		return []string{"§04", "§11"}, nil
	case AreaKnowledge:
		return []string{"§09", "§13"}, nil
	case AreaToolsMCP:
		return []string{"§06", "§14", "§19"}, nil
	case AreaAssurance:
		return []string{"§20", "§37"}, nil
	default:
		return nil, fmt.Errorf("unknown area %q", area)
	}
}

// GuardrailMode — hard block vs soft user-facing refusal.
type GuardrailMode string

const (
	HardBlock    GuardrailMode = "hard"
	SoftResponse GuardrailMode = "soft"
)
```

Синхрон: [Python](../../examples/python/part-10/38-course-agent-assessment-defense.py) · [Bash](../../examples/bash/part-10/38-course-agent-assessment-defense.sh) · [TypeScript](../../examples/typescript/part-10/38-course-agent-assessment-defense.ts) · [C++](../../examples/cpp/part-10/38-course-agent-assessment-defense.cpp) · [Java](../../examples/java/part-10/38-course-agent-assessment-defense.java).

## Чек-лист

- [ ] Понятно, что агент = input + output + knowledge + tools, не только chat.
- [ ] Для своего агента заполнена матрица областей (или N/A с причиной).
- [ ] Есть ссылка на канон I–IX по каждой High-области.
- [ ] Различаете hard block и soft response.
- [ ] LLM-as-judge не единственная защита (EV-03).
- [ ] Confused deputy / malicious MCP учтены, если есть tools.
- [ ] Следующий шаг — практикум §33–37 или Testing Guide.

## Литература

- [Список литературы](../literature.md)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [Meta — Llama Guard 3](https://www.llama.com/docs/model-cards-and-prompt-formats/llama-guard-3/)
- [notes/mapping.md](../mapping.md)

## См. также

- [33 — Course: AI Security Landscape](33-course-ai-security-landscape.md)
- [34 — Course Appendix: практикум](34-course-appendix-agentic-security.md)
- [35 — MCP / Skill Review Workshop](35-mcp-skill-review-workshop.md)
- [36 — Agentic Security Baseline Workshop](36-agentic-security-baseline-workshop.md)
- [37 — AI Agent Security Testing Workshop](37-ai-agent-security-testing-workshop.md)
- [03 — Prompt Injection](../part-2-input-security/03-prompt-injection-detection.md)
- [19 — MCP Security](../part-6-multi-agent-security/19-mcp-security.md)
- [20 — Red Teaming](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md)
