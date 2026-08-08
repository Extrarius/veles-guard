---
tags: [ai-security, course-appendix, assessment, defense, workshop]
часть: "Часть X — Учебное приложение"
статус: готово
обновлено: 2026-08-07
изменения: "Блок «оценка защитных ограничений (Guardrail assessment)» (#guardrail-assessment); мостик к §20 EV-10."
---

# 34 — Course: Agent Assessment and Defense

> Навигация: [Оглавление](../../README.md) · [← Назад](33-course-ai-security-landscape.md) · [Вперёд →](35-course-appendix-agentic-security.md)

*Кратко: учебная карта «что оценивать у агента и чем закрывать» — input / output / RAG / MCP / red team — со ссылками на части I–IX. Без offensive payloads и без вендорного стека.*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-10/34-course-agent-assessment-defense.py) ·
> [Bash](../../examples/bash/part-10/34-course-agent-assessment-defense.sh) ·
> [TypeScript](../../examples/typescript/part-10/34-course-agent-assessment-defense.ts) ·
> [C++](../../examples/cpp/part-10/34-course-agent-assessment-defense.cpp) ·
> [Java](../../examples/java/part-10/34-course-agent-assessment-defense.java)

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

Этот раздел — **навигатор по поверхностям** (input / output / knowledge / tools / assurance) к канону частей I–IX. [§33](33-course-ai-security-landscape.md) — навигатор по **слоям системы**. Не замена threat model ([§02](../part-1-architecture-threats/02-threat-model.md)) и не offensive manual.

## Для кого

| Роль | Как использовать |
|---|---|
| Преподаватель | 20–40 мин после landscape / перед практикумом: классы угроз → §§ |
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

### Blast radius и lethal trifecta (assessment)

Перед матрицей областей зафиксируйте **что агент умеет** (текст → чтение → запись → оболочка → CI / развёртывание — text → read → write → shell → CI / deploy) и где наибольший радиус поражения (blast radius) — [§02](../part-1-architecture-threats/02-threat-model.md).

**Смертельная тройка (Lethal trifecta)** ([Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)): закрытые данные (private data) + недоверенный контент (untrusted content) + исходящий канал (outbound) в одном пути (path). Вопросы оценки (assessment):

1. Есть ли закрытые данные (private data) в контексте при чтении недоверенного issue / PR / email (untrusted)?
2. Есть ли исходящий канал (outbound) — HTTP, публичный PR, отрисовка img / URL (render) — в том же прогоне (run)?
3. Какую **одну** границу удержать, чтобы цепочка оборвалась?

Правило защиты: атакующему нужны все звенья; достаточно сломать одно (недоверенное = данные, не команды — untrusted = data not commands; запись вне белого списка (allowlist) → подтверждение (approval); нет секретов (secrets) у агента; нет исходящего трафика (egress)). Учебные прецеденты по звеньям: [§13](../part-4-output-security/13-egress-control-data-exfiltration.md) (Duo / утечка через изображение — image exfil), [§19](../part-6-multi-agent-security/19-mcp-security.md) (GitHub MCP), [§31](../part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md) (CurXecute).

## Матрица assessment → части I–IX

| Область | Что оценивать (безопасно) | Канон |
|---|---|---|
| **Вход (Input)** | прямое / косвенное внедрение инструкций (direct / indirect prompt injection); обход инструкций через роли | [§03](../part-2-input-security/03-prompt-injection-detection.md) |
| **Выход (Output)** | Небезопасный вывод (разметка, скрипты, утечки) до отрисовки (render) / доверия интерфейсу (UI) | [§11](../part-4-output-security/11-output-validation-fact-checking.md), [§04](../part-2-input-security/04-pii-redaction-content-filtering.md) |
| **Знания / RAG (Knowledge / RAG)** | Отравление документов в базе; извлечение (retrieval) вне списков контроля доступа (ACL); утечка (exfil) через ответ | [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md), [§13](../part-4-output-security/13-egress-control-data-exfiltration.md) |
| **Инструменты / MCP (Tools / MCP)** | Вредоносный / отравленный инструмент (tool); **подставной исполнитель (confused deputy)** — агент действует с чужими правами по подсказке | [§19](../part-6-multi-agent-security/19-mcp-security.md), [§06](../part-3-processing-security/06-rbac-tool-permissions.md) |
| **Уверенность (Assurance)** | Красная команда / оценки (red team / evals) до релиза; LLM-as-judge только как доп. слой; **ограничение (guardrail) как объект** — набор тестов (suite) `EVAL-GUARDRAIL-01` / EV-10 (ложные срабатывания / пропуски (FP/FN), пороги, журнал изменений (changelog)) | [§20](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#guardrail-testing-ev-10), [Testing Guide](../../guides/ai-agent-security-testing-guide.md), [§38](38-ai-agent-security-testing-workshop.md) |

Карта «тема × стандарт»: [notes/mapping.md](../mapping.md).

### Мини-сценарии (учебные, без полезных нагрузок — payloads)

1. **Косвенное внедрение через документ (Indirect injection)** — в базу знаний (knowledge base) попадает текст с инструкциями для модели → проверить извлечение с учётом прав (access-aware retrieval) и изоляцию контекста (§09).
2. **Небезопасный выход (Insecure output)** — модель возвращает разметку, опасную при отрисовке (render) в интерфейсе (UI) → очистка (sanitize) / политика безопасности контента (CSP) / не доверять сырому HTML (raw HTML) (§11).
3. **Подставной исполнитель (Confused deputy)** — сообщение (например, email) маскируется под «системное» и толкает агента вызвать привилегированный инструмент (tool) от имени пользователя → минимальные привилегии (least privilege) + подтверждение (confirmation) (§19, §06, §14).
4. **Вредоносный MCP (Malicious MCP)** — описание / схема (description / schema) скрывает побочный эффект → проверка (review) до установки (install) ([§36](36-mcp-skill-review-workshop.md), §19).

## Ограничения (Guardrails): жёсткая блокировка (hard block) vs мягкий отказ (soft response)

Внешний слой безопасности (safety-слой: классификатор / политика — classifier / policy) ≠ «модель сама откажется».

| Режим | Поведение | Зачем |
|---|---|---|
| **Жёсткая блокировка (Hard block)** | Запрос/ответ отсекается классификатором; дальше конвейер (pipeline) не идёт (или только безопасная заглушка — stub) | Не дать вредоносному вводу/выводу дойти до инструментов (tools) / интерфейса (UI) |
| **Мягкий отказ (Soft response)** | После жёсткой блокировки (hard block) пользователь получает **вежливый отказ** без раскрытия внутренней причины фильтра и без «системного уведомления (system notification)» в ответе | удобство использования (UX); не обучать атакующего точной логике блокировки |

Классификаторы (ориентир): API модерации (moderation APIs), Llama Guard и аналоги — см. [literature.md](../literature.md) (модерация / классификаторы — Moderation / classifiers). Канон детекции на входе — [§03](../part-2-input-security/03-prompt-injection-detection.md); фильтрация контента — [§04](../part-2-input-security/04-pii-redaction-content-filtering.md).

> **Правило:** жёсткая блокировка (hard block) — решение политики; мягкий отказ (soft response) — представление пользователю. Не подменять жёсткую блокировку «надеждой, что модель сама откажется».

<a id="guardrail-assessment"></a>

## Оценка защитных ограничений (Guardrail assessment)

Курс оценивает **наличие процесса** вокруг ограничений (rails) — не заменяет канон набора тестов (suite) / подсчёта (scoring) в [§20 EV-10](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#guardrail-testing-ev-10).

**Вопросы оценки (assessment):**

1. Какие ограничения (rails) есть на пути (вход / извлечение / выход / потоковая передача — input / retrieval / output / streaming)?
2. Есть ли набор тестов (suite) с легитимными (benign) **и** известными атакующими (known-attack) кейсами?
3. Измерены ли ложные срабатывания / пропуски (FP / FN) (и задержка / стоимость (latency / cost), если ограничение дорогое)?
4. Пороги **зафиксированы (frozen)** к конкретному прогону набора (suite run) (не «подкрутили в проде»)?
5. Есть ли журнал изменений (changelog) при смене шаблона / модели / порога (pattern / model / threshold)?

| Класс кейса (кратко) | Зачем в оценке (assessment) |
|---|---|
| легитимный (benign) | контроль ложных срабатываний (FP) |
| известные атаки (known attacks) | контроль пропусков (FN) |
| граница / RAG / инструмент / обфускация (edge / RAG / tool / obfuscation) | покрытие границ — детали в §20 |

```text
Есть жёсткий / мягкий отказ (hard / soft) ≠ ограничение (guardrail) протестировано.
Нет набора тестов (suite) + метрик + журнала изменений (changelog) → EV-10 не закрыт.
```

Связь с ландшафтом: [§33 безопасность и полезность (Safety vs Utility)](33-course-ai-security-landscape.md#safety-vs-utility) — ограничения (rails) сужают автономию; оценка (assessment) проверяет, что сужение измеримо и не «ломает» легитимные сценарии без учёта ложных срабатываний (FP).

## Red team assessment

До релиза: matrix → Expected (контроль срабатывает) → findings → regression ([§38](38-ai-agent-security-testing-workshop.md), [Testing Guide](../../guides/ai-agent-security-testing-guide.md)).

**LLM-as-a-Judge** в suite: отдельная модель/промпт оценивает пару (запрос, ответ / tool trace) на нарушение политики — только **дополнительный** слой (EV-03 в [§20](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md)), не единственная защита. Детерминированные checks и human review для high-risk обязательны.

## Подходы и контрмеры

1. Зафиксировать возможности (capability) / радиус поражения (blast radius) и смертельную тройку (trifecta) ([§02](../part-1-architecture-threats/02-threat-model.md)).
2. Составить матрицу областей (таблица выше) под *свой* агент — вычеркнуть N/A.
3. На каждую High-область — Expected control и раздел канона; достаточно удержать одну границу в цепочке.
4. Ограничения (Guardrails): жёсткий + мягкий отказ раздельно; не светить внутреннюю причину блокировки (block).
5. Оценка ограничений (Guardrail assessment): набор тестов (suite) / FP·FN / зафиксированные пороги (frozen thresholds) / журнал изменений (changelog) → [§20 EV-10](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#guardrail-testing-ev-10).
6. MCP / инструменты (tools): проверка (review) до подключения (connect); подставной исполнитель (confused deputy) в модели угроз (threat model).
7. Перейти к практикуму: [§35](35-course-appendix-agentic-security.md) → [§36](36-mcp-skill-review-workshop.md) → [§37](37-agentic-security-baseline-workshop.md) → [§38](38-ai-agent-security-testing-workshop.md).

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
		return []string{"§20", "§20 EV-10", "§38"}, nil
	default:
		return nil, fmt.Errorf("unknown area %q", area)
	}
}

// GuardrailAssessmentHints — учебные вопросы курса (#guardrail-assessment); подсчёт (scoring) — в §20.
func GuardrailAssessmentHints() []string {
	return []string{
		"ограничения (rails) на пути: input / retrieval / output / streaming?",
		"набор тестов (suite): легитимные (benign) + известные атаки (known-attack)?",
		"измерены ложные срабатывания / пропуски (FP / FN)?",
		"пороги зафиксированы (frozen) к прогону набора (suite run)?",
		"журнал изменений (changelog) при смене rail / threshold?",
	}
}

// GuardrailMode — hard block vs soft user-facing refusal.
type GuardrailMode string

const (
	HardBlock    GuardrailMode = "hard"
	SoftResponse GuardrailMode = "soft"
)
```

Синхрон: [Python](../../examples/python/part-10/34-course-agent-assessment-defense.py) · [Bash](../../examples/bash/part-10/34-course-agent-assessment-defense.sh) · [TypeScript](../../examples/typescript/part-10/34-course-agent-assessment-defense.ts) · [C++](../../examples/cpp/part-10/34-course-agent-assessment-defense.cpp) · [Java](../../examples/java/part-10/34-course-agent-assessment-defense.java).

## Чек-лист

- [ ] Понятно, что агент = input + output + knowledge + tools, не только chat.
- [ ] Для своего агента заполнена матрица областей (или N/A с причиной).
- [ ] Есть ссылка на канон I–IX по каждой High-области.
- [ ] Различаете жёсткую блокировку (hard block) и мягкий отказ (soft response).
- [ ] [Оценка ограничений (Guardrail assessment)](#guardrail-assessment): есть ответы по набору тестов (suite) / FP·FN / порогам (thresholds) / журналу изменений (changelog).
- [ ] Мостик к канону [§20 EV-10](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#guardrail-testing-ev-10) понятен (здесь не дублируем подсчёт (scoring)).
- [ ] LLM-as-judge не единственная защита (EV-03).
- [ ] Confused deputy / malicious MCP учтены, если есть tools.
- [ ] Lethal trifecta проверен; есть план «сломать одно звено».
- [ ] Capability / blast radius зафиксированы до матрицы областей.
- [ ] Следующий шаг — практикум §35–38 или Testing Guide.

## Литература

- [Список литературы](../literature.md)
- [Simon Willison — The lethal trifecta for AI agents](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [Meta — Llama Guard 3](https://www.llama.com/docs/model-cards-and-prompt-formats/llama-guard-3/)
- [notes/mapping.md](../mapping.md)

## См. также

- [33 — Course: AI Security Landscape](33-course-ai-security-landscape.md#safety-vs-utility) — безопасность и полезность (Safety vs Utility)
- [20 — Red Teaming](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#guardrail-testing-ev-10) — канон тестирования ограничений (EV-10)
- [35 — Course Appendix: практикум](35-course-appendix-agentic-security.md)
- [36 — MCP / Skill Review Workshop](36-mcp-skill-review-workshop.md)
- [37 — Agentic Security Baseline Workshop](37-agentic-security-baseline-workshop.md)
- [38 — AI Agent Security Testing Workshop](38-ai-agent-security-testing-workshop.md)
- [03 — Prompt Injection](../part-2-input-security/03-prompt-injection-detection.md)
- [19 — MCP Security](../part-6-multi-agent-security/19-mcp-security.md)
