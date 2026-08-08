---
tags: [ai-security, course-appendix, landscape, frameworks, workshop]
часть: "Часть X — Учебное приложение"
статус: готово
обновлено: 2026-08-08
изменения: "SDLC↔lifecycle, one-pager platform, 7× what-to-log."
---

# 33 — Course: AI Security Landscape

> Навигация: [Оглавление](../../README.md) · [← Назад](../part-9-ai-coding-security/32-ai-coding-security-checklist.md) · [Вперёд →](34-course-agent-assessment-defense.md)

*Кратко: учебная «картина мира» перед практикумом — зачем нужна безопасность AI, слои системы, как пользоваться фреймворками (NIST / OWASP / ATLAS), сквозной сценарий assistant+RAG, ограничения модели и ссылки на разделы частей I–IX. Не замена самому конспекту.*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-10/33-course-ai-security-landscape.py) ·
> [Bash](../../examples/bash/part-10/33-course-ai-security-landscape.sh) ·
> [TypeScript](../../examples/typescript/part-10/33-course-ai-security-landscape.ts) ·
> [C++](../../examples/cpp/part-10/33-course-ai-security-landscape.cpp) ·
> [Java](../../examples/java/part-10/33-course-ai-security-landscape.java)

## Суть

Практикум (§35–38) отвечает на вопрос «что проверить». Этот раздел — на «как думать до чек-листа» по **слоям системы**. Следом [§34 Assessment](34-course-agent-assessment-defense.md) — матрица по **поверхностям** (input / output / tools…); оси разные, не дубли.

1. Внедрение GenAI часто обгоняет контур безопасности (**security gap**).
2. Угрозы сидят на **разных слоях** системы (интерфейс → приложение → данные/модель → агент/инструменты), а не только в «плохом промпте».
3. Фреймворки отвечают на **разные вопросы**; их не смешивают в один список страхов.
4. Маршрут анализа: harm → assets → класс слабости → сценарий атаки → controls → residual risk.
5. Модель — недоверенный компонент: alignment недостаточен, нужны **внешние** guardrails.
6. Учебная группировка угроз ведёт к **разделам частей I–IX** этого справочника (не новый стандарт и не канон Части X).

Дальше по курсу: [§34](34-course-agent-assessment-defense.md) (assessment) → [§35](35-course-appendix-agentic-security.md) (hub) → [§36](36-mcp-skill-review-workshop.md) / [§37](37-agentic-security-baseline-workshop.md) / [§38](38-ai-agent-security-testing-workshop.md).

## Для кого

| Роль | Как использовать |
|---|---|
| Преподаватель | Вводные 20–40 мин перед §34 и воркшопами §36–38 |
| Студент | Карта «куда идти в конспекте» как ориентир перед практикумом |
| Разработчик | Быстрый маршрут harm → раздел, без чтения всего справочника сразу |
| Команда | Общий язык: слой / framework / residual risk |

## Что НЕ является целью

Раздел **не**:

- новый security framework вместо OWASP / NIST / MITRE ATLAS;
- полный threat model продукта (канон — [§02](../part-1-architecture-threats/02-threat-model.md));
- каталог jailbreak-техник или offensive payloads;
- обзор вендорных gateway / облачных сервисов.

## Угроза / контекст

### Security gap

Организации подключают GenAI быстрее, чем выстраивают политики, inventory, least privilege и мониторинг. Итог: агент с инструментами и доступом к данным без сопоставимого контура контроля.

<a id="shadow-ai"></a>

### Теневой ИИ (Shadow AI): запрет / разрешение / контролируемое использование (ban / allow / controlled)

Политика «что делать с генеративным ИИ (GenAI) / агентами» сама становится риском, если нет управляемого контура.

| Режим | Суть | Риск при перекосе |
|---|---|---|
| **Запрет (Ban)** | запрет GenAI / агентов | обходы, личные аккаунты, утечки вне периметра, **потеря наблюдаемости (observability)** |
| **Разрешение (Allow)** | всё разрешено без контура | разрыв безопасности (security gap), теневой ИИ (Shadow AI) внутри «разрешённого» хаоса |
| **Контролируемое (Controlled)** | корпоративный контур ([эталонная платформа](#reference-platform)) | остаточный риск, но учёт (inventory) / политика (policy) / журнал (audit) |

```text
Запрет без альтернативы → люди уходят в личные ChatGPT/Claude → данные и действия вне логов.
```

Учебный вывод: контролируемое использование (controlled usage) ≠ «всё можно» — это путь через платформенные точки контроля, не мимо них.

### Слои системы (threat map)

```text
Interface / External boundary     ← пользователь, каналы входа
        ↓
Application & Control             ← оркестрация, политики, authz
        ↓
AI processing & knowledge         ← LLM, RAG, память, эмбеддинги
        ↓
Execution & Agents                ← tools, MCP, skills, действия вовне
```

На каждом слое свой класс сбоев: injection и jailbreak на входе; misconfig и logic bypass в приложении; poisoning и утечки в знаниях; tool misuse и excessive permissions у агента; отсутствие inventory / monitoring / rollback — сквозь всё.

Иллюстрация (публичный инцидент, не «рецепт атаки»): ранняя волна chat-ботов показала, что **system prompt плохо изолирован** от пользовательского ввода — классический prompt injection / system prompt leakage. Канон защиты — [§03](../part-2-input-security/03-prompt-injection-detection.md), не «ещё один список фраз».

### Пять слоёв агента (учебная карта)

Модель — один из слоёв. Защита нужна на каждом и **между** ними (атака часто на стрелке, не «внутри коробки»):

```text
INPUT / CONTEXT  →  AGENT CORE  →  MEMORY / RAG  →  TOOLS / MCP  →  EXECUTION / INFRA
     ↑ injection        ↑ goal hijack   ↑ poisoning    ↑ tool poison     ↑ RCE / exfil
```

| Слой | Вопрос | Куда в конспекте |
|---|---|---|
| Вход / контекст (Input / Context) | что агент читает как данные, не как команды? | [§03](../part-2-input-security/03-prompt-injection-detection.md), [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md) |
| Ядро агента (Agent Core) | кто выбирает следующий шаг? | [§01](../part-1-architecture-threats/01-introduction.md), [§02](../part-1-architecture-threats/02-threat-model.md) |
| Память / RAG (Memory / RAG) | что запоминает и откуда? | [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md) |
| Инструменты / MCP (Tools / MCP) | что вызывает и с какими правами? | [§06](../part-3-processing-security/06-rbac-tool-permissions.md), [§19](../part-6-multi-agent-security/19-mcp-security.md) |
| Исполнение / инфраструктура (Execution / Infra) | где действует (оболочка / CI / облако — shell, CI, cloud)? | [§08](../part-3-processing-security/08-sandboxing.md), [§31](../part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md) |

На слое вход / контекст (Input / Context) модель часто читает **стиль** текста как роль — метки канала не граница доверия; см. [роли и «суп токенов» (roles / token soup)](#token-soup).

Приоритет границ по **радиусу поражения (blast radius)** и правилу проектирования (design rule) **смертельная тройка (lethal trifecta)** — [§02](../part-1-architecture-threats/02-threat-model.md); исходящий трафик (egress) — [§13](../part-4-output-security/13-egress-control-data-exfiltration.md).

### Учебный жизненный цикл (lifecycle) контролей (не отдельный стандарт)

Контроль принадлежит **стадии**, а не списку советов. Карта к канону I–IX (не фреймворк рядом с OWASP/NIST):

| Стадия | Фокус | Канон |
|---|---|---|
| Проектирование (Design) | границы; что запрещено | [§02](../part-1-architecture-threats/02-threat-model.md), [§25](../part-8-practice/25-security-by-design-checklist.md) |
| Инструменты (Tools) | белый список (allowlist); описание ≠ политика (description ≠ policy) | [§06](../part-3-processing-security/06-rbac-tool-permissions.md), [§19](../part-6-multi-agent-security/19-mcp-security.md), [§36](36-mcp-skill-review-workshop.md) |
| Контекст (Context) | происхождение (provenance); внешнее = данные (external = data) | [§03](../part-2-input-security/03-prompt-injection-detection.md), [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md) |
| Память (Memory) | проверка (check) на входе / выходе | [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md) |
| Идентичность (Identity) | агент не держит сырой секрет (raw secret) | [§10](../part-3-processing-security/10-secrets-management.md) |
| Шлюз (Gateway) | аутентификация, метаданные, журналирование (auth, metadata, logging) на пути tool/MCP | [§19](../part-6-multi-agent-security/19-mcp-security.md), [§15](../part-5-control-observability/15-observability-tracing.md) |
| Красная команда (Red Team) | атаковать себя регулярно | [§20](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md), [§38](38-ai-agent-security-testing-workshop.md) |
| Наблюдение (Observe) | лог достаточный для расследования | [§15](../part-5-control-observability/15-observability-tracing.md), [§16](../part-5-control-observability/16-monitoring-alerting.md), [§23](../part-7-testing-compliance/23-incident-response-recovery.md) |

<a id="sdlc-vs-agent-lifecycle"></a>

### Классический SDLC и учебный lifecycle агента

| | Классический цикл разработки (SDLC) | Учебный lifecycle контролей агента (таблица выше) |
|---|---|---|
| Объект | релизы кода, пайплайн сборки (build) | стадии, на которых живут **контроли** (design → tools → … → observe) |
| «Готово» | тесты / merge / deploy прошли | на каждой стадии есть явный контроль и владелец |
| Риск | дефект в коде / конфиге | недоверенный контекст + инструменты (tools) + исходящий трафик (egress) в одном пути |

```text
Это учебная карта стадий — не отдельный стандарт и не бренд «ADLC»
рядом с OWASP / NIST. Канон контролей — части I–IX.
```

## Обзор фреймворков (Frameworks walkthrough)

Каждый фреймворк — ответ на **свой** вопрос. Не подменять один другим.

| Вопрос | Фреймворк (Framework) | Результат |
|---|---|---|
| Какой вред возможен и кто за риск отвечает? | NIST AI RMF | вред, контекст, владельцы риска (harm, context, risk owners) |
| Что защищаем и от каких источников угроз? | ENISA AI Threat Landscape (при орг. анализе) | активы, источники угроз, воздействие (assets, threat sources, impact) |
| Какой класс слабости у LLM-приложения? | OWASP Top 10 for LLM / Agentic | типичные слабости (weakness): внедрение (injection), избыточная автономия (excessive agency), … |
| Как выглядит поведение атакующего? | MITRE ATLAS | тактики и техники |
| Где менять систему? | Архитектурный слой + этот конспект | ограничения, контроль, мониторинг, откат (constraints, control, monitoring, rollback) |
Карта «тема × стандарт × раздел»: [notes/mapping.md](../mapping.md). Compliance и evidence — [§21](../part-7-testing-compliance/21-compliance-standards.md). Модель угроз агента — [§02](../part-1-architecture-threats/02-threat-model.md).

## Сквозной сценарий: корпоративный assistant + RAG

Учебный маршрут (не полный регистр рисков):

```text
Чат-бот сотрудника (Employee chatbot)
  → ответы из внутренней базы знаний (knowledge base, RAG)
  → при необходимости действия в ITSM / рабочем процессе (workflow)
```

1. **Вред (Harm, NIST-стиль):** утечка данных вне прав пользователя; действие вне процесса; удар по доверию и соответствию требованиям (compliance).
2. **Владельцы (Owners):** продукт, данные, интеграции, безопасность, юридический / compliance (product, data, integrations, security, legal/compliance), владелец бизнес-процесса.
3. **Активы (Assets, ENISA-стиль):** база знаний (knowledge base), извлекатель (retriever), контекст модели (model context), права пользователя, API рабочих процессов (workflow APIs).
4. **Классы слабостей (OWASP LLM, примеры):**

| Сигнал в пайплайне | Класс (ориентир) |
|---|---|
| Недоверенный документ меняет поведение модели | LLM01 Prompt Injection |
| В контекст попали данные вне прав пользователя | LLM02 Sensitive Information Disclosure |
| Retrieval вернул лишний / устаревший фрагмент | LLM08 Vector / Embedding Weaknesses |
| Ассистент инициировал действие со слишком широкими правами | LLM06 Excessive Agency |

5. **Сценарий (ATLAS-стиль, сжато):** начальный доступ (Initial Access) — вредоносный документ в базе → исполнение (Execution) — внедрение (injection) через RAG-контекст → сбор / утечка (Collection / Exfiltration) — ответ вне списков контроля доступа (ACL) → воздействие (Impact) — неавторизованное действие.
6. **Где рвать цепочку:** доверенные источники (trusted sources), извлечение с учётом прав (access-aware retrieval), минимальные привилегии (least privilege), подтверждение критичных действий, маскирование (masking), мониторинг (monitoring), откат (rollback).
7. **Остаточный риск (Residual risk):** внедрение инструкций (prompt injection) полностью не «лечится» — принимается ограниченный риск при детектировании и откате; решение фиксирует владелец риска (risk owner).

Вывод (takeaway): не список страхов, а **маршрут от вреда к архитектурному решению**. Детали RAG/памяти — [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md); выход — [§11](../part-4-output-security/11-output-validation-fact-checking.md) / [§12](../part-4-output-security/12-hallucination-detection.md) / [§13](../part-4-output-security/13-egress-control-data-exfiltration.md).

## Почему классическая ИБ переносится плохо

| Обычное ПО | AI-системы |
|---|---|
| Детерминированная логика | Вероятностная генерация |
| Код отделён от данных (в идеале) | Инструкции и данные — одни и те же токены |
| Можно читать и ревьюить исходники контроля | Поведение частично в весах / контексте |
| SAST / DAST / WAF закрывают известные классы | Нужны дополнительные слои: политика (policy), авторизация инструментов (tool authz), проверки выхода (output checks), человек в контуре (HITL) |

<a id="token-soup"></a>

### Роли и «суп токенов» (roles / token soup)

Для модели контекст — **один поток** текста. Метки `system` / `user` / `tool` / `think` (и аналоги) — **теги (tags)**, а не граница доверия (trust boundary). Стиль недоверенного текста может перебить настоящий тег роли.

```text
Путаница ролей (role confusion) / подделка цепочки рассуждений (CoT Forgery):
тег ≠ доверие. Политика на стоке (policy on sink), не «модель поняла роль».
```

Канон угрозы и stop-patterns — [§03 путаница ролей / подделка CoT (Role confusion / CoT Forgery)](../part-2-input-security/03-prompt-injection-detection.md#role-confusion). На курсе: оценка (assessment) — [§34](34-course-agent-assessment-defense.md#guardrail-assessment); набор тестов (suite) — [§20 EV-12](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#role-confusion-evals-ev-12). Готовые полезные нагрузки (payloads) не публикуем.

Аналогия с SQL-внедрением (SQL injection) полезна как «смешение инструкций и данных», но **не** как «уже решённая задача»: у естественного языка нет формальной грамматики для параметризованных запросов (parameterized queries). Поэтому полагаться только на «умный системный промпт (system prompt)» нельзя — нужны внешние контроли ([§03](../part-2-input-security/03-prompt-injection-detection.md), [§06](../part-3-processing-security/06-rbac-tool-permissions.md), [§14](../part-5-control-observability/14-human-in-the-loop.md)).

## Четыре ограничения ожидания

| Ограничение | Смысл | Практика |
|---|---|---|
| Hallucinations | Оптимизация правдоподобия, не истины | Источники, cross-check, [§12](../part-4-output-security/12-hallucination-detection.md) |
| Knowledge cutoff | Без инструментов нет «сегодня» | Tools / retrieval с политикой; не доверять «фактам из головы» |
| Нет памяти между сессиями | Новый чат = чистый лист | Истина в файлах/системах, не в истории чата |
| Context window | Видит только то, что в окне; переполнение = забывание | Короткие сессии, приоритет инструкций; **Lost in the Middle** — внимание слабеет в середине длинного контекста |

Дополнительно: **alignment** (SFT/RLHF и аналоги) снижает вероятность вредного поведения, но не гарантирует безопасность — знания остаются в весах, jailbreak ищет обход. Решение для продукта: **внешние guardrails** (части II–V), а не «модель уже aligned». Конфликт целей helpful / harmless / honest и reward hacking в оценках — [§20 Evaluation Gaming](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#evaluation-gaming--reward-hacking). Рассуждения модели ≠ source of truth — [§15 Reasoning vs actions](../part-5-control-observability/15-observability-tracing.md#reasoning-vs-actions).

## Эволюция угроз (кратко)

```text
Base models / prompts  →  RAG  →  autonomous agents  →  MCP / tools  →  multi-agent
     leaks, PI              ACL/RAG                   excessive agency    poisoning     cascading
```

Чем выше автономия и число инструментов, тем важнее inventory, least privilege, sandbox, egress и kill-switch — не только «фильтр на промпт».

<a id="safety-vs-utility"></a>

### Безопасность и полезность (Safety vs Utility)

```text
Безопасность сужает автономию (autonomy), а не возможности (capabilities).
```

Агент может оставаться «умным» — те же модели и инструменты (tools) — но **без** тихого запуска оболочки / сети / записи (silent shell / network / write). Возможность (capability) ≠ право действовать без политики (policy) и человека в контуре (HITL). Контрпример: «полный доступ модели к shell ради удобства» vs «тот же инструмент через подтверждение (approval) + песочницу (sandbox)» ([§06](../part-3-processing-security/06-rbac-tool-permissions.md), [§14](../part-5-control-observability/14-human-in-the-loop.md), [§28](../part-9-ai-coding-security/28-coding-agent-permissions-sandbox-approval.md)). Как оценивать сами ограничения (rails) — [§34 оценка защитных ограничений (Guardrail assessment)](34-course-agent-assessment-defense.md#guardrail-assessment).

## Zero Trust for AI

```text
Не доверять входам модели
Не доверять выходам модели
Не давать лишних прав
Проверять каждое значимое действие
```

Модель = недоверенный компонент. Критичные действия → [HITL](../part-5-control-observability/14-human-in-the-loop.md). Права на tools → [§06](../part-3-processing-security/06-rbac-tool-permissions.md). Слоистая защита (guardrails + data controls + isolation + observability + governance) обязательна; ни один слой не даёт абсолютной гарантии.

<a id="reference-platform"></a>

## Эталонная корпоративная платформа (reference platform, учебная схема)

Ответ на [теневой ИИ (Shadow AI) / контролируемое использование (controlled)](#shadow-ai): агент **не** ходит к моделям, инструментам (tools) и внешним сервисам напрямую — только через платформенные точки (канон в частях I–IX, здесь карта курса).

**One-pager (на один экран):** агент → ограничения данных (data guardrails) → шлюз к модели (AI Gateway) → шлюз инструментов (Tool Gateway) / доверенный реестр (Trusted Registry) → песочница (sandbox) → журнал (audit) / политика (policy) / аварийный стоп (kill-switch) → модель | tools | egress. Прямой SDK / MCP «мимо» шлюза — антипаттерн.

```text
Ограничения данных (Data Guardrails) → Шлюз к модели (AI Gateway)
  → Шлюз инструментов (Tool Gateway) → Доверенный реестр (Trusted Registry)
  → Песочница (Sandbox) → Журнал / мониторинг (Audit / Monitoring)
  → Движок политики (Policy engine) → Аварийный стоп (Kill switch)
```

| Узел | Куда в конспекте |
|---|---|
| Ограничения данных (Data Guardrails) | [§04](../part-2-input-security/04-pii-redaction-content-filtering.md) (D0–D4, санитизация — sanitization) |
| Шлюз к модели (AI Gateway) | [§13 маршрутизация вывода (inference)](../part-4-output-security/13-egress-control-data-exfiltration.md#inference-routing) |
| Шлюз инструментов (Tool Gateway) | [§06](../part-3-processing-security/06-rbac-tool-permissions.md#tool-gateway) |
| Доверенный реестр (Trusted Registry) | [§19](../part-6-multi-agent-security/19-mcp-security.md#trusted-tool-registry) |
| Песочница (Sandbox) | [§08](../part-3-processing-security/08-sandboxing.md) |
| Журнал / мониторинг (Audit / Monitoring) | [§15](../part-5-control-observability/15-observability-tracing.md), [§16](../part-5-control-observability/16-monitoring-alerting.md) |
| Движок политики (Policy engine) | [§06](../part-3-processing-security/06-rbac-tool-permissions.md), [§14](../part-5-control-observability/14-human-in-the-loop.md) |
| Аварийный стоп (Kill switch) | [§17](../part-5-control-observability/17-circuit-breaker-kill-switch.md) |

```text
Среда выполнения LLM / агента (LLM / agent runtime)
  → узлы платформы (platform hops) → модель | инструменты (tools) | исходящий трафик (egress).
Прямой вызов SDK модели или MCP «мимо» шлюза / реестра (gateway / registry) — антипаттерн курса.
```

Класс риска агента как продукта (R0–R3) — канон [§25](../part-8-practice/25-security-by-design-checklist.md#agent-risk-class); учебная оценка — [§34 оценка по классу риска](34-course-agent-assessment-defense.md#agent-risk-assessment).

## Навигатор: слой системы → части I–IX

Учебный навигатор по слоям системы (см. threat map выше) к разделам **частей I–IX**. Не отдельный стандарт — только карта «куда читать в конспекте».

| Слой | Фокус | Куда в конспекте |
|---|---|---|
| Интерфейс / внешняя граница (Interface / External) | внедрение инструкций (prompt injection), обход ограничений (jailbreak), частота / отказ в обслуживании (rate / DoS) на входе | [§03](../part-2-input-security/03-prompt-injection-detection.md), [§04](../part-2-input-security/04-pii-redaction-content-filtering.md), [§05](../part-2-input-security/05-rate-limiting-quotas-token-bombing.md) |
| Приложение и управление (Application & Control) | авторизация (authz), политика (policy), оркестрация (orchestration), человек в контуре (HITL), аварийный стоп (kill-switch) | [§06](../part-3-processing-security/06-rbac-tool-permissions.md), [§07](../part-3-processing-security/07-parameter-validation-schema.md), [§14](../part-5-control-observability/14-human-in-the-loop.md), [§17](../part-5-control-observability/17-circuit-breaker-kill-switch.md) |
| AI-обработка и знания (AI processing & knowledge) | RAG / память, выход (output), исходящий трафик (egress), галлюцинации (hallucination), персональные данные (PII) | [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md), [§11](../part-4-output-security/11-output-validation-fact-checking.md), [§12](../part-4-output-security/12-hallucination-detection.md), [§13](../part-4-output-security/13-egress-control-data-exfiltration.md), [§04](../part-2-input-security/04-pii-redaction-content-filtering.md) |
| Исполнение и агенты (Execution & Agents) | инструменты (tools), песочница (sandbox), MCP, цепочка поставок (supply chain), мультиагентность (multi-agent), coding-агенты | [§08](../part-3-processing-security/08-sandboxing.md), [§18](../part-6-multi-agent-security/18-inter-agent-security.md), [§19](../part-6-multi-agent-security/19-mcp-security.md), [§22](../part-7-testing-compliance/22-supply-chain-security.md), [§28](../part-9-ai-coding-security/28-coding-agent-permissions-sandbox-approval.md)–[§31](../part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md) |
| Контроль и уверенность (Control & assurance) | наблюдаемость (observability), красная команда (red team), реагирование на инциденты (IR), соответствие требованиям (compliance) | [§15](../part-5-control-observability/15-observability-tracing.md), [§16](../part-5-control-observability/16-monitoring-alerting.md), [§20](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md), [§21](../part-7-testing-compliance/21-compliance-standards.md), [§23](../part-7-testing-compliance/23-incident-response-recovery.md) |

Связанные фреймворки (OWASP LLM/Agentic/MCP, NIST, ATLAS) — в [literature.md](../literature.md) и [mapping.md](../mapping.md); эта таблица **не заменяет** их коды.

## Мониторинг (шпаргалка → §15 / §16)

| Что | Примеры |
|---|---|
| Журналы (Logs) | вызовы инструментов и аргументы (tool calls + args) с редактированием (redaction), идентификаторы пользователя / сессии (user / session ids), метки времени (timestamps); не хранить секреты |
| Метрики (Metrics) | токены на пользователя (tokens / user), задержка (latency), частота срабатывания ограничений (guardrail trigger rate), частота отказов (refusal rate), доля ПДн на выходе (PII-in-output rate) |
| Оповещения (Alerts) | паттерны обхода ограничений (jailbreak) и многоходовая эскалация (multi-turn); аномальный расход токенов (tokens); рост отказов (refusal); ПДн (PII) на выходе |

<a id="what-to-log"></a>

### Что логировать у агента (учебные 7 полей)

Компактный минимум для курса — канон полей и redaction в [§15](../part-5-control-observability/15-observability-tracing.md) (в т.ч. [поля inference / routing](../part-5-control-observability/15-observability-tracing.md#inference-audit-fields)):

1. идентификатор прогона / корреляции (run / correlation id);
2. агент / личность (agent / identity);
3. вызовы инструментов (tool calls): имя + решение политики (policy decision);
4. модель / провайдер / место вывода (model / provider / inference location) — маршрутизация (routing);
5. идентификаторы фрагментов RAG / извлечения (RAG / retrieval chunk ids) или явный N/A;
6. подтверждения / человек в контуре (approvals / HITL);
7. исходящий трафик / внешние хосты (egress / external hosts).

Не логировать секреты и mapping депсевдонимизации (см. §15).

Канон: [§15](../part-5-control-observability/15-observability-tracing.md), [§16](../part-5-control-observability/16-monitoring-alerting.md). Kill-switch / IR — [§17](../part-5-control-observability/17-circuit-breaker-kill-switch.md), [§23](../part-7-testing-compliance/23-incident-response-recovery.md) (здесь не дублируем playbook).

## Подходы и контрмеры

1. Начать с **вреда и владельцев риска**, не с длинного списка CVE-стиля.
2. Привязать слабость к **слою системы** и к **разделу** частей I–IX (таблица выше).
3. Для политики GenAI выбрать режим [запрет / разрешение / контролируемое (ban / allow / controlled)](#shadow-ai); запрет без альтернативы → теневой ИИ (Shadow AI).
4. Для контролируемого режима — путь через [эталонную платформу (reference platform)](#reference-platform), не прямой доступ к модели / инструментам (tools).
5. Для помощника + RAG (assistant + RAG) пройти маршрут вред (harm) → остаточный риск (residual risk) один раз на учебном сценарии.
6. Считать модель недоверенной: нулевое доверие для ИИ (Zero Trust for AI) + человек в контуре (HITL) на критичных действиях.
7. После картины мира — [§34 оценка (Assessment)](34-course-agent-assessment-defense.md) (в т.ч. [класс риска R0–R3](34-course-agent-assessment-defense.md#agent-risk-assessment)), затем практикум: [§35](35-course-appendix-agentic-security.md) → §36–38.

## Пример (Go): навигатор слоя → разделы

Иллюстрация: по слою системы вернуть рекомендуемые якоря конспекта (не runtime-policy).

```go
package landscape

import "fmt"

// Layer — учебный слой threat map §33, не стандарт compliance.
type Layer string

const (
	LayerInterface   Layer = "interface"
	LayerAppControl  Layer = "app_control"
	LayerAIKnowledge Layer = "ai_knowledge"
	LayerExecution   Layer = "execution"
	LayerAssurance   Layer = "assurance"
)

// SectionRefs — короткие якоря вида "§03", "§19".
func SectionRefs(layer Layer) ([]string, error) {
	switch layer {
	case LayerInterface:
		return []string{"§03", "§04", "§05"}, nil
	case LayerAppControl:
		return []string{"§06", "§07", "§14", "§17"}, nil
	case LayerAIKnowledge:
		return []string{"§04", "§09", "§11", "§12", "§13"}, nil
	case LayerExecution:
		return []string{"§08", "§18", "§19", "§22", "§28", "§31"}, nil
	case LayerAssurance:
		return []string{"§15", "§16", "§20", "§21", "§23"}, nil
	default:
		return nil, fmt.Errorf("unknown layer %q", layer)
	}
}

// SafetyNarrowsAutonomyNotCapability — тезис #safety-vs-utility (учебный ориентир, не runtime-flag).
const SafetyNarrowsAutonomyNotCapability = true

// UsageMode — политика GenAI / агентов (#shadow-ai); не runtime-enforcer.
type UsageMode string

const (
	UsageBan        UsageMode = "ban"
	UsageAllow      UsageMode = "allow"
	UsageControlled UsageMode = "controlled"
)

// PlatformHops — узлы эталонной платформы (#reference-platform) в порядке пути.
func PlatformHops() []string {
	return []string{
		"data_guardrails", "ai_gateway", "tool_gateway", "trusted_registry",
		"sandbox", "audit_monitoring", "policy_engine", "kill_switch",
	}
}
```

Синхрон: [Python](../../examples/python/part-10/33-course-ai-security-landscape.py) · [Bash](../../examples/bash/part-10/33-course-ai-security-landscape.sh) · [TypeScript](../../examples/typescript/part-10/33-course-ai-security-landscape.ts) · [C++](../../examples/cpp/part-10/33-course-ai-security-landscape.cpp) · [Java](../../examples/java/part-10/33-course-ai-security-landscape.java).

## Чек-лист

- [ ] Понятен разрыв безопасности (security gap): внедрение vs контур контроля.
- [ ] Для политики GenAI назван режим [запрет / разрешение / контролируемое (ban / allow / controlled)](#shadow-ai) и риск теневого ИИ (Shadow AI) при запрете без альтернативы.
- [ ] Понятна [эталонная платформа (reference platform)](#reference-platform): one-pager путь; агент не ходит к моделям / инструментам (tools) напрямую.
- [ ] Понятен контраст [SDLC ↔ учебный lifecycle агента](#sdlc-vs-agent-lifecycle): не бренд «ADLC», канон — части I–IX.
- [ ] Названы [7 учебных полей журнала агента](#what-to-log) (вкл. RAG chunks / routing) со ссылкой на §15.
- [ ] Умеете указать слой системы для своей угрозы (interface / app / AI-data / agents / assurance).
- [ ] Для одной системы прошли вопрос → framework → результат (хотя бы NIST + OWASP + ATLAS).
- [ ] На сценарии assistant+RAG зафиксированы harm, residual risk и risk owner.
- [ ] Модель считается недоверенной; названы внешние ограничения (guardrails), не только выравнивание (alignment).
- [ ] Понятно [безопасность и полезность (Safety vs Utility)](#safety-vs-utility): безопасность сужает автономию (silent actions), не «вырезает» возможности (capabilities) модели.
- [ ] Понятны [роли и «суп токенов» (roles / token soup)](#token-soup): теги ролей ≠ граница доверия; канон [§03](../part-2-input-security/03-prompt-injection-detection.md#role-confusion).
- [ ] Выбран слой в навигаторе и открыты соответствующие §§ частей I–IX.
- [ ] Следующий шаг — [§34 оценка (Assessment)](34-course-agent-assessment-defense.md) (ограничения + [класс риска R0–R3](34-course-agent-assessment-defense.md#agent-risk-assessment)), затем практикум §35–38.

## Литература

- [Список литературы](../literature.md)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [NIST AI Risk Management Framework](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [ENISA — AI cybersecurity (publications hub)](https://www.enisa.europa.eu/topics/artificial-intelligence)
- [notes/mapping.md](../mapping.md) — тема × стандарты × раздел

## См. также

- [01 — Введение](../part-1-architecture-threats/01-introduction.md)
- [02 — Threat Model](../part-1-architecture-threats/02-threat-model.md)
- [03 — Путаница ролей / подделка CoT (Role confusion / CoT Forgery)](../part-2-input-security/03-prompt-injection-detection.md#role-confusion)
- [13 — Шлюз к модели (AI Gateway) / вывод (inference)](../part-4-output-security/13-egress-control-data-exfiltration.md#inference-routing)
- [25 — Класс риска агента R0–R3](../part-8-practice/25-security-by-design-checklist.md#agent-risk-class)
- [21 — Compliance и Standards](../part-7-testing-compliance/21-compliance-standards.md)
- [34 — Course: Agent Assessment and Defense](34-course-agent-assessment-defense.md#guardrail-assessment) — оценка защитных ограничений (Guardrail assessment) → EV-10; [оценка по классу риска R0–R3](34-course-agent-assessment-defense.md#agent-risk-assessment); [PR→CI→exfil](34-course-agent-assessment-defense.md#pr-ci-exfil-trace); [анти-паттерны](34-course-agent-assessment-defense.md#anti-patterns-course)
- [SDLC ↔ lifecycle](#sdlc-vs-agent-lifecycle); [что логировать у агента](#what-to-log); [эталонная платформа](#reference-platform)
- [35 — Course Appendix: практикум](35-course-appendix-agentic-security.md)
- [36 — MCP / Skill Review Workshop](36-mcp-skill-review-workshop.md)
- [37 — Agentic Security Baseline Workshop](37-agentic-security-baseline-workshop.md)
- [38 — AI Agent Security Testing Workshop](38-ai-agent-security-testing-workshop.md)
