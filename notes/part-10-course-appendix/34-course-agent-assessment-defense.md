---
tags: [ai-security, course-appendix, assessment, defense, workshop]
часть: "Часть X — Учебное приложение"
статус: готово
обновлено: 2026-08-23
изменения: "Beyond-model assessment (#beyond-model-assessment): память / фреймворк / sandbox-рантайм / endpoint, не только модель."
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

<a id="pr-ci-exfil-trace"></a>

### Учебный след: недоверенный PR → CI → утечка (exfil)

Пошаговый путь без полезных нагрузок (payloads) — на каждом шаге, **где рвётся** цепочка:

| Шаг | Что происходит | Где рвётся |
|---|---|---|
| 1 | Недоверенный PR / issue (текст, комментарий) попадает в контекст агента или CI | [недоверенный вход PR/issue](../part-9-ai-coding-security/29-prompt-injection-via-code-comments-docs.md#pr-issue-untrusted-input): **данные ≠ команды** (data ≠ commands) |
| 2 | Агент / job читает закрытый контекст (репо, secrets env, соседние файлы) | нет секретов (secrets) у агента; изоляция среды; least privilege |
| 3 | Модель предлагает tool / shell / MCP / запись в workflow | allowlist инструментов (tools); schema; **не** always-allow |
| 4 | Действие уходит во внешний канал (HTTP, публичный артефакт, render URL) | [egress](../part-4-output-security/13-egress-control-data-exfiltration.md); deny-by-default |
| 5 | Запись / merge / privileged MCP без человека | [HITL](../part-5-control-observability/14-human-in-the-loop.md) на write; review gate |

Канон по звеньям: [§19](../part-6-multi-agent-security/19-mcp-security.md), [§13](../part-4-output-security/13-egress-control-data-exfiltration.md), [§29](../part-9-ai-coding-security/29-prompt-injection-via-code-comments-docs.md#pr-issue-untrusted-input), [§31](../part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md). Цель упражнения — назвать **одно** звено, которое удержите в своём контуре.

## Матрица assessment → части I–IX

| Область | Что оценивать (безопасно) | Канон |
|---|---|---|
| **Вход (Input)** | прямое / косвенное внедрение инструкций (direct / indirect prompt injection); обход инструкций через роли / [путаница ролей (role confusion)](../part-2-input-security/03-prompt-injection-detection.md#role-confusion); логи / алерты / телеметрия и вывод инструментов — тот же класс ([внешние входы](#external-data-inputs)) | [§03](../part-2-input-security/03-prompt-injection-detection.md#role-confusion), [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md#security-telemetry-injection), [§16](../part-5-control-observability/16-monitoring-alerting.md#telemetry-as-agent-input) |
| **Выход (Output)** | Небезопасный вывод (разметка, скрипты, утечки) до отрисовки (render) / доверия интерфейсу (UI) | [§11](../part-4-output-security/11-output-validation-fact-checking.md), [§04](../part-2-input-security/04-pii-redaction-content-filtering.md) |
| **Знания / RAG (Knowledge / RAG)** | Отравление документов в базе; извлечение (retrieval) вне списков контроля доступа (ACL); утечка (exfil) через ответ | [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md), [§13](../part-4-output-security/13-egress-control-data-exfiltration.md) |
| **Инструменты / MCP (Tools / MCP)** | Вредоносный / отравленный инструмент (tool); **подставной исполнитель (confused deputy)** — агент действует с чужими правами по подсказке | [§19](../part-6-multi-agent-security/19-mcp-security.md), [§06](../part-3-processing-security/06-rbac-tool-permissions.md) |
| **Уверенность (Assurance)** | Красная команда / оценки (red team / evals) до релиза; LLM-as-judge только как доп. слой; **ограничение (guardrail) как объект** — набор тестов (suite) `EVAL-GUARDRAIL-01` / EV-10 (ложные срабатывания / пропуски (FP/FN), пороги, журнал изменений (changelog)) | [§20](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#guardrail-testing-ev-10), [Testing Guide](../../guides/ai-agent-security-testing-guide.md), [§38](38-ai-agent-security-testing-workshop.md) |
| **Обвязка (Harness)** | Названы обвязка + версия, не только модель; смена обвязки при той же модели; расширения ревьюятся как policy, не как skill ([якорь](#harness-assessment)) | [глоссарий](../glossary.md), [§26](../part-9-ai-coding-security/26-ai-coding-agent-threat-model.md), [§31](../part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md#harness-extension), [EV-15](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#split-context-evals-ev-15) |
| **Стек вне модели** | Память / state store; orchestration-стек; движок песочницы; endpoint / локальные MCP ([якорь](#beyond-model-assessment)) | [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md#memory-storage-layer), [§22](../part-7-testing-compliance/22-supply-chain-security.md#orchestration-stack), [§08](../part-3-processing-security/08-sandboxing.md#sandbox-runtime), [§33](33-course-ai-security-landscape.md#shadow-ai), [§19](../part-6-multi-agent-security/19-mcp-security.md#endpoint-inventory) |

Карта «тема × стандарт»: [notes/mapping.md](../mapping.md).

### Мини-сценарии (учебные, без полезных нагрузок — payloads)

1. **Косвенное внедрение через документ (Indirect injection)** — в базу знаний (knowledge base) попадает текст с инструкциями для модели → проверить извлечение с учётом прав (access-aware retrieval) и изоляцию контекста (§09).
2. **Небезопасный выход (Insecure output)** — модель возвращает разметку, опасную при отрисовке (render) в интерфейсе (UI) → очистка (sanitize) / политика безопасности контента (CSP) / не доверять сырому HTML (raw HTML) (§11).
3. **Подставной исполнитель (Confused deputy)** — сообщение (например, email) маскируется под «системное» и толкает агента вызвать привилегированный инструмент (tool) от имени пользователя → минимальные привилегии (least privilege) + подтверждение (confirmation) (§19, §06, §14).
4. **Вредоносный MCP (Malicious MCP)** — описание / схема (description / schema) скрывает побочный эффект → проверка (review) до установки (install) ([§36](36-mcp-skill-review-workshop.md), §19).
5. **Изготовленное подтверждение / подделанное рассуждение (Manufactured approval / forged reasoning)** — в контексте появляется текст «как уже одобрил человек» или reasoning-стиль → подтверждение (approval) только из внеполосного шлюза (out-of-band gate) + запись решения ([§14](../part-5-control-observability/14-human-in-the-loop.md#manufactured-approval)); подделанное рассуждение (forged reasoning) ≠ источник истины (source of truth) ([§15](../part-5-control-observability/15-observability-tracing.md#forged-cot)). **Без полезных нагрузок (payloads).**

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
6. Может ли агент **изготовить себе подтверждение (approval)** или принять **подделанное рассуждение (forged reasoning)** за внутреннюю трассу / человека в контуре (HITL)? Канон — [§03](../part-2-input-security/03-prompt-injection-detection.md#role-confusion), [§14](../part-5-control-observability/14-human-in-the-loop.md#manufactured-approval), [§15](../part-5-control-observability/15-observability-tracing.md#forged-cot); набор тестов (suite) — [§20 EV-12](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#role-confusion-evals-ev-12).
7. Какой тип judge (SLM / SLM ensemble / LLM arbitrator) и зафиксированы ли пороги `usual` / `strict`? Канон — [§03 pipeline](../part-2-input-security/03-prompt-injection-detection.md#guardrail-pipeline-router).
8. Назван ли [отраслевой сценарий](33-course-ai-security-landscape.md#enterprise-scenarios) и что удерживаем (UX / скорость / эксперимент) vs что контролируем (данные / write / inference)? Канон — [§33 Safety vs Utility](33-course-ai-security-landscape.md#safety-vs-utility).

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

<a id="access-layers"></a>

#### Access layers (учебная рамка)

Четыре оси, чтобы на курсе спросить «где стоит rail». **Не** канон слоёв справочника: не заменяет [pipeline §03](../part-2-input-security/03-prompt-injection-detection.md#guardrail-pipeline-router), [five control points §04](../part-2-input-security/04-pii-redaction-content-filtering.md#five-control-points), [навигатор §33](33-course-ai-security-landscape.md).

```text
teaching frame != control canon
```

| Ось | Вопрос | Канон |
|---|---|---|
| LLM | что видит / генерирует модель | [§03](../part-2-input-security/03-prompt-injection-detection.md), [§11](../part-4-output-security/11-output-validation-fact-checking.md) |
| Context | что попало в контекст | [§03](../part-2-input-security/03-prompt-injection-detection.md), [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md) |
| Action | какой tool / какое действие | [§06](../part-3-processing-security/06-rbac-tool-permissions.md), [§07](../part-3-processing-security/07-parameter-validation-schema.md) |
| Access | к каким данным / egress | [§13](../part-4-output-security/13-egress-control-data-exfiltration.md), [§08](../part-3-processing-security/08-sandboxing.md) |

<a id="agent-risk-assessment"></a>

## Оценка по классу риска агента (Agent risk assessment, R0–R3)

**Дополняет** [оценку защитных ограничений (Guardrail assessment)](#guardrail-assessment) / [§20 EV-10](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#guardrail-testing-ev-10), **не заменяет**: ограничения (rails) проверяют «сработали ли контроли»; R0–R3 — «агент как продукт с правильным классом и минимумом контролей».

Канон лестницы и матрицы — [§25 Класс риска агента](../part-8-practice/25-security-by-design-checklist.md#agent-risk-class); спецификация до запуска — [паспорт агента (agent passport)](../../templates/agent-passport.md). Здесь — учебные вопросы курса.

**Вопросы оценки (assessment):**

1. Назначен ли класс **R0 / R1 / R2 / R3** и есть ли обоснование?
2. Есть ли человек-владелец (human owner) и заполненный **паспорт (passport)** (цель, данные, модели, инструменты — tools, аварийный стоп — kill-switch)?
3. Для **R2+**: вывод модели (inference) идёт через [шлюз к модели (AI Gateway)](../part-4-output-security/13-egress-control-data-exfiltration.md#inference-routing), а не напрямую к SDK?
4. Инструменты (tools) / MCP — через [шлюз инструментов (Tool Gateway)](../part-3-processing-security/06-rbac-tool-permissions.md#tool-gateway) / [доверенный реестр (Trusted Registry)](../part-6-multi-agent-security/19-mcp-security.md#trusted-tool-registry)?
5. Человек в контуре (HITL) / аварийный стоп (kill-switch) / журнал (audit) соответствуют классу (см. матрицу §25)?

| Класс | Что спросить на курсе (кратко) |
|---|---|
| **R0** песочница (sandbox) | нет prod-данных / инструментов записи (write tools)? изолирован от prod? |
| **R1** помощник (assistant) | паспорт (passport) + владелец (owner)? белый список инструментов (allowlist)? журнал (audit)? |
| **R2** операционный (operational) | шлюз к модели (AI Gateway) + шлюз / реестр инструментов? HITL на запись (write)? аварийный стоп? красная команда (red team)? |
| **R3** критический (critical) | всё из R2 + усиленный HITL, владелец реагирования на инциденты (IR owner), карта соответствия (compliance map) ([§21](../part-7-testing-compliance/21-compliance-standards.md))? |

```text
Набор тестов ограничений (guardrail suite) зелёный
  ≠ класс риска назначен и контроли по классу закрыты.
Нет паспорта (passport) / класса → производственный шлюз (production gate) §25 не пройден
  (учебно: агент «не готов к релизу»).
```

Связь с ландшафтом: [§33 эталонная платформа (reference platform)](33-course-ai-security-landscape.md#reference-platform) — куда «садится» агент при контролируемом использовании (controlled usage); [теневой ИИ (Shadow AI)](33-course-ai-security-landscape.md#shadow-ai) — что бывает без контура.

<a id="harness-assessment"></a>

## Оценка модели, обвязки и расширений (Harness assessment)

Оценка «модели» без обвязки неполная: `Agent = Model + Harness`. Вопросы ниже — учебный якорь; канон — [глоссарий: Harness](../glossary.md), [§26](../part-9-ai-coding-security/26-ai-coding-agent-threat-model.md), [§31](../part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md). Не каталог харнессов и не «как построить обвязку».

```text
model eval != harness eval
same model != same posture
harness extension != skill
```

**Вопросы оценки (assessment):**

1. Названы ли **обвязка и версия**, не только модель? Определение — [глоссарий: Harness](../glossary.md); сущность — [§26](../part-9-ai-coding-security/26-ai-coding-agent-threat-model.md).
2. При смене обвязки на **той же модели** переоценивали ли posture / eval matrix (harness × model)? Канон — [§31](../part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md), [§20 EV-15](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#split-context-evals-ev-15).
3. Какие **расширения обвязки** подключены — ревью как изменение policy (owner, pin, diff review), не как контент задачи? Канон — [§31 `#harness-extension`](../part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md#harness-extension).

```text
Зелёный прогон на модели ≠ обвязка и её расширения оценены.
```

Не путать с [классом R0–R3](#agent-risk-assessment) (продукт, не версия обвязки) и с [внешними входами](#external-data-inputs) (данные, не control plane).

<a id="beyond-model-assessment"></a>

## Оценка стека вне модели (Beyond-model assessment)

Оценка «модели» неполная без runtime-стека: память, фреймворк, движок песочницы, endpoint. Вопросы ниже — учебный якорь; канон в частях I–IX. Не разбор инцидентов и не каталог продуктов. Не путать с [обвязкой](#harness-assessment) (control plane, не эти четыре поверхности).

```text
model eval != stack eval
memory store != prompt memory
sandbox image != sandbox engine
registry != discovery
```

**Вопросы оценки (assessment):**

1. Память / state store: query / serde / tenant на load? Канон — [§09 `#memory-storage-layer`](../part-3-processing-security/09-memory-isolation-context-sanitization.md#memory-storage-layer), [EV-18](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#memory-runtime-evals-ev-18).
2. Orchestration-стек — тот же аудит, что backend (SAST / SCA / serialization)? Канон — [§22 `#orchestration-stack`](../part-7-testing-compliance/22-supply-chain-security.md#orchestration-stack).
3. Движок песочницы pinned; containment покрывает process / memory / tenant? Канон — [§08 `#sandbox-runtime`](../part-3-processing-security/08-sandboxing.md#sandbox-runtime), [`EVAL-CONTAINMENT-01`](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#containment-evals-eval-containment-01).
4. Endpoint / локальные MCP в inventory, не только сеть? Канон — [§33 `#shadow-ai`](33-course-ai-security-landscape.md#shadow-ai), [§19 `#endpoint-inventory`](../part-6-multi-agent-security/19-mcp-security.md#endpoint-inventory).

```text
Зелёный прогон на модели ≠ стек вне модели оценён.
```

<a id="external-data-inputs"></a>

## Оценка внешних входов (External data as input)

Агент читает больше, чем «чат пользователя». Всё прочитанное — **данные**, не команды (data ≠ commands). Вопросы ниже — учебный якорь; канон остаётся в частях I–IX.

| Класс внешних данных | Канон |
|---|---|
| Документы / база знаний (RAG) | [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md) |
| Web и файлы | [§03](../part-2-input-security/03-prompt-injection-detection.md), [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md) |
| PR / issue / комментарии | [§29](../part-9-ai-coding-security/29-ai-generated-code-review-spec-driven.md#pr-issue-untrusted-input), [§27](../part-9-ai-coding-security/27-repository-instructions-attack-surface.md) |
| Вывод инструментов и каналы MCP | [§19](../part-6-multi-agent-security/19-mcp-security.md#split-context-mcp-injection) |
| Логи / алерты / телеметрия / error-отчёты | [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md#security-telemetry-injection), [§16](../part-5-control-observability/16-monitoring-alerting.md#telemetry-as-agent-input) |
| Выводы других агентов | [§18](../part-6-multi-agent-security/18-inter-agent-security.md#agent-generated-artifact-poisoning) |

**Вопросы оценки (assessment):**

1. Какие внешние данные агент читает (перечислить по таблице, вычеркнуть N/A)?
2. Может ли агент **по тем же данным** выполнить привилегированное действие (оболочка — shell, чтение секретов, запись, изменение инфраструктуры)?
3. Помечен ли источник каждого фрагмента контекста (метка источника — source label, не тег роли — role tag)?
4. Есть ли путь «прочитал → выполнил» без внеполосного подтверждения (out-of-band approval)?
5. Какое **одно** звено рвём в своём контуре (связка со смертельной тройкой (lethal trifecta) выше и [следом PR→CI→exfil](#pr-ci-exfil-trace))?

```text
Данные из системы безопасности (лог, алерт) — тоже внешний вход.
Прочитал ≠ уполномочен выполнить.
```

## Red team assessment

До релиза: matrix → Expected (контроль срабатывает) → findings → regression ([§38](38-ai-agent-security-testing-workshop.md), [Testing Guide](../../guides/ai-agent-security-testing-guide.md)).

**LLM-as-a-Judge** в suite: отдельная модель/промпт оценивает пару (запрос, ответ / tool trace) на нарушение политики — только **дополнительный** слой (EV-03 в [§20](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md)), не единственная защита. Детерминированные checks и human review для high-risk обязательны.

## Подходы и контрмеры

1. Зафиксировать возможности (capability) / радиус поражения (blast radius) и смертельную тройку (trifecta) ([§02](../part-1-architecture-threats/02-threat-model.md)).
2. Составить матрицу областей (таблица выше) под *свой* агент — вычеркнуть N/A.
3. На каждую High-область — Expected control и раздел канона; достаточно удержать одну границу в цепочке.
4. Ограничения (Guardrails): жёсткий + мягкий отказ раздельно; не светить внутреннюю причину блокировки (block).
5. Оценка ограничений (Guardrail assessment): набор тестов (suite) / FP·FN / зафиксированные пороги (frozen thresholds) / журнал изменений (changelog) → [§20 EV-10](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#guardrail-testing-ev-10).
6. Оценка по классу риска (Agent risk assessment, R0–R3): паспорт (passport) / владелец (owner) / шлюз (gateway) / реестр (registry) по [якорю](#agent-risk-assessment) → канон [§25](../part-8-practice/25-security-by-design-checklist.md#agent-risk-class).
7. Оценка обвязки (Harness assessment): модель + обвязка + расширения по [якорю](#harness-assessment) → канон [глоссарий](../glossary.md) / [§26](../part-9-ai-coding-security/26-ai-coding-agent-threat-model.md) / [§31](../part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md#harness-extension).
8. Оценка стека вне модели (Beyond-model assessment): память / фреймворк / sandbox-рантайм / endpoint по [якорю](#beyond-model-assessment).
9. MCP / инструменты (tools): проверка (review) до подключения (connect); подставной исполнитель (confused deputy) в модели угроз (threat model).
10. Перейти к практикуму: [§35](35-course-appendix-agentic-security.md) → [§36](36-mcp-skill-review-workshop.md) → [§37](37-agentic-security-baseline-workshop.md) → [§38](38-ai-agent-security-testing-workshop.md).

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
		"агент может изготовить себе подтверждение (approval) / принять подделанное рассуждение (forged reasoning) за HITL? (§03/§14/§15; EV-12)",
	}
}

// RiskClassAssessmentHints — учебные вопросы (#agent-risk-assessment); матрица контролей — в §25.
func RiskClassAssessmentHints() []string {
	return []string{
		"назначен класс R0–R3 и есть обоснование?",
		"есть человек-владелец (human owner) и заполненный паспорт агента (agent passport)?",
		"для R2+: вывод (inference) через шлюз к модели (AI Gateway), не прямой SDK?",
		"инструменты (tools) / MCP через шлюз инструментов (Tool Gateway) / доверенный реестр (Trusted Registry)?",
		"человек в контуре (HITL) / аварийный стоп (kill-switch) / журнал (audit) соответствуют классу (§25)?",
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

<a id="anti-patterns-course"></a>

## Анти-паттерны курса (8)

Учебная сводка «чего не делать» — детали в частях I–IX и [§33 эталонная платформа](33-course-ai-security-landscape.md#reference-platform):

1. Доверять только system prompt как защите.
2. Always-allow / `*` на инструменты (tools).
3. SDK модели или MCP «мимо» шлюза / реестра (gateway / registry).
4. Тело PR / issue как инструкции агенту (вместо правила data ≠ commands).
5. Сырой ход рассуждения (raw CoT) как единственный источник истины (SoT).
6. Нет человека в контуре (HITL) на запись (write) / привилегированных действиях.
7. Секреты (secrets) в среде или контексте агента.
8. Логировать mapping псевдонимов / депсевдонимизацию (см. [§33 what-to-log](33-course-ai-security-landscape.md#what-to-log), §15).

## Чек-лист

- [ ] Понятно, что агент = input + output + knowledge + tools, не только chat.
- [ ] Для своего агента заполнена матрица областей (или N/A с причиной).
- [ ] Есть ссылка на канон I–IX по каждой High-области.
- [ ] Различаете жёсткую блокировку (hard block) и мягкий отказ (soft response).
- [ ] [Оценка ограничений (Guardrail assessment)](#guardrail-assessment): есть ответы по набору тестов (suite) / FP·FN / порогам (thresholds) / журналу изменений (changelog).
- [ ] Названы [Access layers](#access-layers) (LLM / Context / Action / Access) как учебная рамка, не канон слоёв.
- [ ] Назван отраслевой сценарий и пара control vs utility (что контролируем / что не теряем) — [§33](33-course-ai-security-landscape.md#enterprise-scenarios).
- [ ] Учтён вопрос про изготовленное подтверждение (manufactured approval) / подделанное рассуждение (forged reasoning); канон §03 / §14 / §15; suite [§20 EV-12](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#role-confusion-evals-ev-12).
- [ ] Мостик к канону [§20 EV-10](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#guardrail-testing-ev-10) понятен (здесь не дублируем подсчёт (scoring)).
- [ ] [Оценка по классу риска R0–R3 (Agent risk assessment)](#agent-risk-assessment): класс, паспорт / владелец (passport / owner), шлюз / реестр (gateway / registry) по классу; не подменяет оценку защитных ограничений (Guardrail assessment).
- [ ] [Оценка обвязки (Harness assessment)](#harness-assessment): названы обвязка + версия; смена обвязки переоценена; расширения ревьюятся как policy.
- [ ] [Оценка стека вне модели (Beyond-model assessment)](#beyond-model-assessment): память / state store, orchestration-стек, движок песочницы, endpoint inventory (не только модель).
- [ ] LLM-as-judge не единственная защита (EV-03).
- [ ] Confused deputy / malicious MCP учтены, если есть tools.
- [ ] Lethal trifecta проверен; есть план «сломать одно звено».
- [ ] Пройден [учебный след PR→CI→exfil](#pr-ci-exfil-trace): названо звено «где рвётся».
- [ ] Заполнен [список внешних входов](#external-data-inputs); для каждого сказано, может ли агент по этим данным действовать.
- [ ] Проверены [8 анти-паттернов курса](#anti-patterns-course) на своём агенте (или N/A с причиной).
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

- [33 — Course: AI Security Landscape](33-course-ai-security-landscape.md#safety-vs-utility) — безопасность и полезность (Safety vs Utility); [отраслевые сценарии](33-course-ai-security-landscape.md#enterprise-scenarios); [теневой ИИ (Shadow AI)](33-course-ai-security-landscape.md#shadow-ai); [эталонная платформа (reference platform)](33-course-ai-security-landscape.md#reference-platform); [роли / суп токенов (token soup)](33-course-ai-security-landscape.md#token-soup); [SDLC ↔ lifecycle](33-course-ai-security-landscape.md#sdlc-vs-agent-lifecycle); [что логировать](33-course-ai-security-landscape.md#what-to-log)
- [Учебный след PR→CI→exfil](#pr-ci-exfil-trace); [анти-паттерны курса](#anti-patterns-course); [внешние входы](#external-data-inputs); [обвязка / расширения](#harness-assessment); [стек вне модели](#beyond-model-assessment)
- [09 — Memory storage layer](../part-3-processing-security/09-memory-isolation-context-sanitization.md#memory-storage-layer) · [22 — Orchestration-стек](../part-7-testing-compliance/22-supply-chain-security.md#orchestration-stack) · [08 — Sandbox-рантайм](../part-3-processing-security/08-sandboxing.md#sandbox-runtime) · [19 — Endpoint inventory](../part-6-multi-agent-security/19-mcp-security.md#endpoint-inventory)
- [Глоссарий — Harness](../glossary.md) · [26 — сущность обвязки](../part-9-ai-coding-security/26-ai-coding-agent-threat-model.md) · [31 — Harness extension](../part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md#harness-extension) · [20 — EV-15 harness × model](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#split-context-evals-ev-15)
- [09 — Security Telemetry Injection](../part-3-processing-security/09-memory-isolation-context-sanitization.md#security-telemetry-injection) — логи / алерты как untrusted
- [16 — телеметрия как вход](../part-5-control-observability/16-monitoring-alerting.md#telemetry-as-agent-input)
- [19 — Split-context MCP injection](../part-6-multi-agent-security/19-mcp-security.md#split-context-mcp-injection)
- [25 — Класс риска агента R0–R3](../part-8-practice/25-security-by-design-checklist.md#agent-risk-class) — канон матрицы / производственный шлюз (production gate)
- [Шаблоны — паспорт агента (agent passport)](../../templates/agent-passport.md)
- [20 — Red Teaming](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#guardrail-testing-ev-10) — канон тестирования ограничений (EV-10); [путаница ролей (EV-12)](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#role-confusion-evals-ev-12)
- [35 — Course Appendix: практикум](35-course-appendix-agentic-security.md)
- [36 — MCP / Skill Review Workshop](36-mcp-skill-review-workshop.md)
- [37 — Agentic Security Baseline Workshop](37-agentic-security-baseline-workshop.md)
- [38 — AI Agent Security Testing Workshop](38-ai-agent-security-testing-workshop.md)
- [03 — Guardrail pipeline + judge / similarity](../part-2-input-security/03-prompt-injection-detection.md#guardrail-pipeline-router)
- [03 — Путаница ролей / подделка CoT (Role confusion / CoT Forgery)](../part-2-input-security/03-prompt-injection-detection.md#role-confusion)
- [14 — Изготовленное подтверждение (Manufactured approval)](../part-5-control-observability/14-human-in-the-loop.md#manufactured-approval)
- [15 — Подделанный CoT (Forged CoT)](../part-5-control-observability/15-observability-tracing.md#forged-cot)
- [19 — MCP Security](../part-6-multi-agent-security/19-mcp-security.md)
