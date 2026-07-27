---
tags: [ai-security, course-appendix, landscape, frameworks, workshop]
часть: "Часть X — Учебное приложение"
статус: готово
обновлено: 2026-07-27
изменения: "Нумерация Части X: landscape = §33 (первый)."
---

# 33 — Course: AI Security Landscape

> Навигация: [Оглавление](../../README.md) · [← Назад](../part-9-ai-coding-security/32-ai-coding-security-checklist.md) · [Вперёд →](34-course-appendix-agentic-security.md)

*Кратко: учебная «картина мира» перед практикумом — зачем нужна безопасность AI, слои системы, как пользоваться фреймворками (NIST / OWASP / ATLAS), сквозной сценарий assistant+RAG, ограничения модели и ссылки на разделы частей I–IX. Не замена самому конспекту.*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-10/33-course-ai-security-landscape.py) ·
> [Bash](../../examples/bash/part-10/33-course-ai-security-landscape.sh) ·
> [TypeScript](../../examples/typescript/part-10/33-course-ai-security-landscape.ts) ·
> [C++](../../examples/cpp/part-10/33-course-ai-security-landscape.cpp) ·
> [Java](../../examples/java/part-10/33-course-ai-security-landscape.java)

## Суть

Практикум (§34–37) отвечает на вопрос «что проверить». Этот раздел — на «как думать до чек-листа»:

1. Внедрение GenAI часто обгоняет контур безопасности (**security gap**).
2. Угрозы сидят на **разных слоях** системы (интерфейс → приложение → данные/модель → агент/инструменты), а не только в «плохом промпте».
3. Фреймворки отвечают на **разные вопросы**; их не смешивают в один список страхов.
4. Маршрут анализа: harm → assets → класс слабости → сценарий атаки → controls → residual risk.
5. Модель — недоверенный компонент: alignment недостаточен, нужны **внешние** guardrails.
6. Учебная группировка угроз ведёт к **разделам частей I–IX** этого справочника (не новый стандарт и не канон Части X).

Дальше по курсу: [§34](34-course-appendix-agentic-security.md) (набор артефактов) → [§35](35-mcp-skill-review-workshop.md) / [§36](36-agentic-security-baseline-workshop.md) / [§37](37-ai-agent-security-testing-workshop.md).

## Для кого

| Роль | Как использовать |
|---|---|
| Преподаватель | Вводные 20–40 мин перед воркшопами §35–37 |
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

## Frameworks walkthrough

Каждый фреймворк — ответ на **свой** вопрос. Не подменять один другим.

| Вопрос | Framework | Результат |
|---|---|---|
| Какой вред возможен и кто за риск отвечает? | NIST AI RMF | harm, context, risk owners |
| Что защищаем и от каких источников угроз? | ENISA AI Threat Landscape (при орг. анализе) | assets, threat sources, impact |
| Какой класс слабости у LLM-приложения? | OWASP Top 10 for LLM / Agentic | типичные weakness (injection, excessive agency, …) |
| Как выглядит поведение атакующего? | MITRE ATLAS | тактики и техники |
| Где менять систему? | Архитектурный слой + этот конспект | constraints, control, monitoring, rollback |

Карта «тема × стандарт × раздел»: [notes/mapping.md](../mapping.md). Compliance и evidence — [§21](../part-7-testing-compliance/21-compliance-standards.md). Модель угроз агента — [§02](../part-1-architecture-threats/02-threat-model.md).

## Сквозной сценарий: корпоративный assistant + RAG

Учебный маршрут (не полный регистр рисков):

```text
Employee chatbot
  → ответы из внутренней knowledge base (RAG)
  → при необходимости действия в ITSM / workflow
```

1. **Harm (NIST-стиль):** утечка данных вне прав пользователя; действие вне процесса; удар по доверию и compliance.
2. **Owners:** product, data, integrations, security, legal/compliance, владелец бизнес-процесса.
3. **Assets (ENISA-стиль):** knowledge base, retriever, model context, права пользователя, workflow APIs.
4. **Классы слабостей (OWASP LLM, примеры):**

| Сигнал в пайплайне | Класс (ориентир) |
|---|---|
| Недоверенный документ меняет поведение модели | LLM01 Prompt Injection |
| В контекст попали данные вне прав пользователя | LLM02 Sensitive Information Disclosure |
| Retrieval вернул лишний / устаревший фрагмент | LLM08 Vector / Embedding Weaknesses |
| Ассистент инициировал действие со слишком широкими правами | LLM06 Excessive Agency |

5. **Сценарий (ATLAS-стиль, сжато):** Initial Access (вредоносный документ в базе) → Execution (injection через RAG-контекст) → Collection/Exfiltration (ответ вне ACL) → Impact (неавторизованное действие).
6. **Где рвать цепочку:** trusted sources, access-aware retrieval, least privilege, подтверждение критичных действий, masking, monitoring, rollback.
7. **Residual risk:** prompt injection полностью не «лечится» — принимается ограниченный риск при детектировании и откате; решение фиксирует risk owner.

Takeaway: не список страхов, а **маршрут от вреда к архитектурному решению**. Детали RAG/памяти — [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md); выход — [§11](../part-4-output-security/11-output-validation-fact-checking.md) / [§12](../part-4-output-security/12-hallucination-detection.md) / [§13](../part-4-output-security/13-egress-control-data-exfiltration.md).

## Почему классическая ИБ переносится плохо

| Обычное ПО | AI-системы |
|---|---|
| Детерминированная логика | Вероятностная генерация |
| Код отделён от данных (в идеале) | Инструкции и данные — одни и те же токены |
| Можно читать и ревьюить исходники контроля | Поведение частично в весах / контексте |
| SAST/DAST/WAF закрывают известные классы | Нужны дополнительные слои: policy, tool authz, output checks, HITL |

Аналогия с SQL injection полезна как «смешение инструкций и данных», но **не** как «уже решённая задача»: у естественного языка нет формальной грамматики для parameterized queries. Поэтому полагаться только на «умный system prompt» нельзя — нужны внешние контроли ([§03](../part-2-input-security/03-prompt-injection-detection.md), [§06](../part-3-processing-security/06-rbac-tool-permissions.md), [§14](../part-5-control-observability/14-human-in-the-loop.md)).

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

## Zero Trust for AI

```text
Не доверять входам модели
Не доверять выходам модели
Не давать лишних прав
Проверять каждое значимое действие
```

Модель = недоверенный компонент. Критичные действия → [HITL](../part-5-control-observability/14-human-in-the-loop.md). Права на tools → [§06](../part-3-processing-security/06-rbac-tool-permissions.md). Слоистая защита (guardrails + data controls + isolation + observability + governance) обязательна; ни один слой не даёт абсолютной гарантии.

## Навигатор: слой системы → части I–IX

Учебный навигатор по слоям системы (см. threat map выше) к разделам **частей I–IX**. Не отдельный стандарт — только карта «куда читать в конспекте».

| Слой | Фокус | Куда в конспекте |
|---|---|---|
| Interface / External | Prompt injection, jailbreak, rate/DoS на входе | [§03](../part-2-input-security/03-prompt-injection-detection.md), [§04](../part-2-input-security/04-pii-redaction-content-filtering.md), [§05](../part-2-input-security/05-rate-limiting-quotas-token-bombing.md) |
| Application & Control | authz, policy, orchestration, HITL, kill-switch | [§06](../part-3-processing-security/06-rbac-tool-permissions.md), [§07](../part-3-processing-security/07-parameter-validation-schema.md), [§14](../part-5-control-observability/14-human-in-the-loop.md), [§17](../part-5-control-observability/17-circuit-breaker-kill-switch.md) |
| AI processing & knowledge | RAG/память, output, egress, hallucination, PII | [§09](../part-3-processing-security/09-memory-isolation-context-sanitization.md), [§11](../part-4-output-security/11-output-validation-fact-checking.md), [§12](../part-4-output-security/12-hallucination-detection.md), [§13](../part-4-output-security/13-egress-control-data-exfiltration.md), [§04](../part-2-input-security/04-pii-redaction-content-filtering.md) |
| Execution & Agents | tools, sandbox, MCP, supply chain, multi-agent, coding agents | [§08](../part-3-processing-security/08-sandboxing.md), [§18](../part-6-multi-agent-security/18-inter-agent-security.md), [§19](../part-6-multi-agent-security/19-mcp-security.md), [§22](../part-7-testing-compliance/22-supply-chain-security.md), [§28](../part-9-ai-coding-security/28-coding-agent-permissions-sandbox-approval.md)–[§31](../part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md) |
| Control & assurance | observability, red team, IR, compliance | [§15](../part-5-control-observability/15-observability-tracing.md), [§16](../part-5-control-observability/16-monitoring-alerting.md), [§20](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md), [§21](../part-7-testing-compliance/21-compliance-standards.md), [§23](../part-7-testing-compliance/23-incident-response-recovery.md) |

Связанные фреймворки (OWASP LLM/Agentic/MCP, NIST, ATLAS) — в [literature.md](../literature.md) и [mapping.md](../mapping.md); эта таблица **не заменяет** их коды.

## Мониторинг (шпаргалка → §15 / §16)

| Что | Примеры |
|---|---|
| Logs | tool calls + args (с redaction), user/session ids, timestamps; не хранить секреты |
| Metrics | tokens / user, latency, guardrail trigger rate, refusal rate, PII-in-output rate |
| Alerts | jailbreak-паттерны и multi-turn эскалация; аномальный расход tokens; рост refusal; PII на выходе |

Канон: [§15](../part-5-control-observability/15-observability-tracing.md), [§16](../part-5-control-observability/16-monitoring-alerting.md). Kill-switch / IR — [§17](../part-5-control-observability/17-circuit-breaker-kill-switch.md), [§23](../part-7-testing-compliance/23-incident-response-recovery.md) (здесь не дублируем playbook).

## Подходы и контрмеры

1. Начать с **вреда и владельцев риска**, не с длинного списка CVE-стиля.
2. Привязать слабость к **слою системы** и к **разделу** частей I–IX (таблица выше).
3. Для RAG/assistant пройти маршрут harm → residual risk один раз на учебном сценарии.
4. Считать модель недоверенной: Zero Trust + HITL на критичных действиях.
5. После картины мира — практикум: [§34](34-course-appendix-agentic-security.md) → §35–37.

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
```

Синхрон: [Python](../../examples/python/part-10/33-course-ai-security-landscape.py) · [Bash](../../examples/bash/part-10/33-course-ai-security-landscape.sh) · [TypeScript](../../examples/typescript/part-10/33-course-ai-security-landscape.ts) · [C++](../../examples/cpp/part-10/33-course-ai-security-landscape.cpp) · [Java](../../examples/java/part-10/33-course-ai-security-landscape.java).

## Чек-лист

- [ ] Понятен security gap (внедрение vs контур контроля).
- [ ] Умеете указать слой системы для своей угрозы (interface / app / AI-data / agents / assurance).
- [ ] Для одной системы прошли вопрос → framework → результат (хотя бы NIST + OWASP + ATLAS).
- [ ] На сценарии assistant+RAG зафиксированы harm, residual risk и risk owner.
- [ ] Модель считается недоверенной; названы внешние guardrails (не только alignment).
- [ ] Выбран слой в навигаторе и открыты соответствующие §§ частей I–IX.
- [ ] Следующий шаг — [§34](34-course-appendix-agentic-security.md) или воркшоп §35–37.

## Литература

- [Список литературы](../literature.md)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [NIST AI Risk Management Framework](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [ENISA — AI cybersecurity (publications hub)](https://www.enisa.europa.eu/topics/artificial-intelligence)
- [notes/mapping.md](../mapping.md) — тема × стандарты × раздел

## См. также

- [34 — Course Appendix: практикум](34-course-appendix-agentic-security.md)
- [35 — MCP / Skill Review Workshop](35-mcp-skill-review-workshop.md)
- [36 — Agentic Security Baseline Workshop](36-agentic-security-baseline-workshop.md)
- [37 — AI Agent Security Testing Workshop](37-ai-agent-security-testing-workshop.md)
- [01 — Введение](../part-1-architecture-threats/01-introduction.md)
- [02 — Модель угроз](../part-1-architecture-threats/02-threat-model.md)
- [21 — Compliance и Standards](../part-7-testing-compliance/21-compliance-standards.md)
