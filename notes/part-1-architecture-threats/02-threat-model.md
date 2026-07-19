---
tags: [ai-security, конспект]
часть: "Часть I — Архитектура и угрозы"
статус: готово
обновлено: 2026-07-19
изменения: "ADI: spoofed trusted metadata (STRIDE + короткий сценарий); ссылка на §03."
---

# 02 — Модель угроз (Threat Model)

> Навигация: [Оглавление](../../README.md) · [← Назад](01-introduction.md) · [Вперёд →](../part-2-input-security/03-prompt-injection-detection.md)

*Кратко: threat model для AI-агента строится через DFD, trust boundaries, STRIDE по элементам диаграммы и риск-реестр с уровнем High / Medium / Low.*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-1/02-threat-model.py) ·
> [TypeScript](../../examples/typescript/part-1/02-threat-model.ts)

## Суть

**Модель угроз** — это формальное описание того, что мы защищаем, кто может атаковать, через какие входы, какие компоненты участвуют в обработке и какие последствия будут при ошибке или компрометации.

Для AI-агента threat model нужна до выбора конкретных guardrails, потому что защита зависит от архитектуры:

- какие данные видит агент;
- какие tools доступны;
- есть ли память;
- есть ли RAG;
- есть ли shell / browser / database access;
- есть ли внешние агенты;
- какие действия выполняются автоматически;
- где проходит trust boundary.

Базовый порядок:

```text
1. Описать активы
2. Описать акторов
3. Нарисовать DFD
4. Отметить trust boundaries
5. Пройти STRIDE по элементам DFD
6. Оценить риск: High / Medium / Low
7. Привязать контрмеры
8. Зафиксировать в risk register
```

## Что защищаем

Типовые активы в агентной системе:

| Актив | Пример | Почему важен |
|---|---|---|
| User data | запросы, документы, история | может содержать персональные или коммерческие данные |
| System instructions | system prompt, developer prompt | определяют допустимое поведение агента |
| Tool credentials | API keys, OAuth tokens, service accounts | дают доступ к внешним системам |
| Memory | long-term memory, vector store, session context | может хранить секреты или poisoned context |
| Tool outputs | ответы API, shell output, web pages | могут содержать вредные инструкции |
| Logs | trace, audit log, raw prompts | могут раскрывать секреты и действия пользователя |
| External systems | CRM, DB, Git, email, calendar | могут быть изменены агентом |
| Budget / quotas | токены, API limits, деньги | могут быть исчерпаны через loop / DoS |

## Кто атакует

| Актор | Что может делать |
|---|---|
| Пользователь | напрямую отправляет вредный prompt |
| Внешний автор документа | внедряет indirect prompt injection в PDF, web page, email |
| Внешний сервис | возвращает poisoned tool output |
| Инсайдер | пытается расширить доступ агента или извлечь данные |
| Компрометированный tool / MCP server | подменяет описание инструмента, схему или результат |
| Другой агент | передаёт вредное сообщение в multi-agent workflow |
| AI-driven attacker | использует автономного агента для разведки, генерации эксплойтов, перебора учётных данных и lateral movement на скорости машины |
| Agentic Threat Actor (ATA) | capability атаки доставляется AI-агентом end-to-end (не human-driven toolkit): recon → credentials → pivot → destructive playbook |

Задокументирован первый масштабный AI-оркестрированный взлом (кампания GTG-1002, 2025): агент выполнял ~80–90% операций, человек вмешивался в 4–6 точках. Защитный вывод для threat model: открытый или доступный исходный код упрощает автоматическую разведку — assume adversary с доступом к исходникам. Подробнее — в [literature.md](../literature.md).

### Agentic Threat Actor / Agentic Ransomware (JADEPUFFER)

**Agentic Threat Actor (ATA)** — оператор, чья атакующая capability реализуется AI-агентом от initial access до цели, а не классическим human-driven ransomware toolkit.

**JADEPUFFER** (Sysdig Threat Research, 2026) — задокументированный случай **agentic ransomware**: LLM-driven кампания с автоматическим вымогательством через destructive действия против production database. Ниже — threat narrative для модели угроз, **без** offensive payloads и PoC эксплуатации.

#### Сценарий

```text
Exposed AI/agent framework (e.g. Langflow)
  + known CVE / missing auth on control plane
  → RCE on internet-facing host with API keys / cloud creds in env
  → automated recon + credential sweep (.env, keys, wallets, DB/config)
  → lateral / pivot to production DB / config services
  → destructive database extortion playbook
```

Типичные предпосылки:

- internet-facing agent builder / workflow UI без жёсткой auth/network segmentation;
- provider API keys и cloud credentials в environment на том же хосте;
- default/weak credentials на внутренних сервисах, доступных с хоста агента;
- production DB или config plane достижимы из скомпрометированного AI-adjacent host.

#### Detection signals

| Сигнал | Почему характерен для ATA |
|---|---|
| Verbose self-narrating scripts / LLM-style annotations в payloads | LLM часто «комментирует» шаги и приоритеты так, как люди редко пишут |
| Rapid retries / plan–act–observe–adjust | fail → fix за секунды (адаптация параметров, повтор) |
| Массовый параллельный поиск secrets | `.env`, API keys, wallets, cloud/DB credentials сразу несколькими категориями |
| Быстрый переход recon → destructive | после сбора кредов — сразу destructive/extortion на DB, без долгой «тихой» фазы |

#### STRIDE (на что смотреть в DFD)

| STRIDE | В сценарии ATA |
|---|---|
| Elevation of Privilege | RCE на agent control plane → права хоста / доступ к env secrets |
| Information Disclosure | credential sweep, dump config/DB, exfil staging |
| Tampering | destructive DB / config changes как рычаг вымогательства |

Threat model должен учитывать **не только** защиту *своего* агента, но и то, что противник может применять agentic capability **против** вашей инфраструктуры (особенно exposed AI frameworks). IR — [§23](../part-7-testing-compliance/23-incident-response-recovery.md).

## DFD Level 1 — агент с границами доверия

```mermaid
flowchart LR
    User[External Entity: User]
    Admin[External Entity: Admin / Operator]

    subgraph TB1["Trust Boundary: Untrusted Inputs"]
        UserInput[Process: User Input]
        Docs[(Data Store: Uploaded Docs / Web / Email)]
    end

    subgraph TB2["Trust Boundary: Agent Runtime"]
        ContextBuilder[Process: Context Builder]
        Planner[Process: LLM Planner]
        Policy[Process: Policy Engine]
        ToolRouter[Process: Tool Router]
        OutputValidator[Process: Output Validator]
        Audit[Process: Audit Logger]
    end

    subgraph TB3["Trust Boundary: Internal Storage"]
        Memory[(Data Store: Memory / Vector Store)]
        Logs[(Data Store: Logs / Traces)]
        Config[(Data Store: Policies / Tool Config)]
    end

    subgraph TB4["Trust Boundary: External Providers"]
        LLM[External System: LLM API]
        Tools[External System: Tools / APIs / Shell / DB]
        ExternalAgent[External Entity: External Agent]
    end

    User -->|task / prompt| UserInput
    Admin -->|policy / config changes| Config

    UserInput -->|normalized input| ContextBuilder
    Docs -->|retrieved content| ContextBuilder
    Memory -->|stored context| ContextBuilder
    Config -->|rules / scopes| Policy

    ContextBuilder -->|prompt + context| Planner
    Planner -->|LLM request| LLM
    LLM -->|plan / tool request| Planner

    Planner -->|proposed tool call| Policy
    Policy -->|allowed call| ToolRouter
    Policy -->|deny / approval required| Audit

    ToolRouter -->|tool call| Tools
    Tools -->|observation| ToolRouter
    ExternalAgent -->|message / delegation| ContextBuilder

    ToolRouter -->|observation| Planner
    Planner -->|draft answer| OutputValidator
    OutputValidator -->|final answer| User

    Planner -->|memory write| Memory
    Audit -->|events| Logs
    ToolRouter -->|tool event| Audit
    OutputValidator -->|output event| Audit
```

Ключевые trust boundaries:

| Boundary | Что отделяет | Почему важно |
|---|---|---|
| Untrusted Inputs → Agent Runtime | пользовательский ввод, документы, web, email | здесь появляются prompt injection и poisoned content |
| Agent Runtime → External Providers | LLM API, tools, shell, DB | здесь возможны утечки, опасные действия и supply chain |
| Agent Runtime → Internal Storage | память, логи, политики | здесь возможны memory poisoning, утечки логов, изменение конфигурации |
| External Agent → Agent Runtime | сообщения других агентов | здесь возможны подмена цели и insecure inter-agent communication |

## STRIDE для AI-агента

STRIDE — это способ пройтись по компонентам системы и проверить шесть классов угроз.

| STRIDE | Вопрос для агента | Пример |
|---|---|---|
| Spoofing | Кто-то выдаёт себя за пользователя, tool или агента? | внешний агент отправляет сообщение от имени доверенного агента; tool response подставляет fake `author` / provenance |
| Tampering | Можно ли изменить вход, память, tool output или policy? | документ содержит скрытую инструкцию; поля `id`/`uri` в JSON выглядят «trusted», но не проверены policy |
| Repudiation | Можно ли отрицать выполнение действия? | агент отправил письмо, но нет audit log с причиной вызова tool |
| Information Disclosure | Может ли агент раскрыть данные? | секрет из памяти попал в ответ или внешний API |
| Denial of Service | Можно ли перегрузить агента или ресурсы? | token bombing, бесконечный loop, дорогие API calls |
| Elevation of Privilege | Может ли агент получить больше прав? | tool вызван вне роли или с более широким scope |

## STRIDE по элементам DFD

| DFD element | STRIDE | Угроза | Risk | Контрмеры |
|---|---|---|---|---|
| User Input | Tampering | Prompt injection меняет цель или ограничения задачи | High | input validation, prompt injection detection, context isolation |
| Uploaded Docs / Web / Email | Tampering | Indirect prompt injection в документе влияет на план агента | High | treat content as data, sanitization, retrieval filtering |
| Uploaded Docs / Tool Output | Spoofing / Tampering | Agent Data Injection: untrusted поля маскируются под trusted metadata (resource ID, provenance, author) | High | trusted format ≠ trusted data; deterministic validation ID/URL ([§03](../part-2-input-security/03-prompt-injection-detection.md#agent-data-injection-adi)) |
| Context Builder | Information Disclosure | В контекст попадают секреты или лишние данные | High | data minimization, PII redaction, need-to-know context |
| LLM Planner | Tampering | Модель принимает tool output как новую инструкцию | High | instruction/data separation, tool output labeling |
| Policy Engine | Elevation of Privilege | Ошибка политики разрешает опасный tool call | High | deny by default, RBAC, scopes, tests |
| Tool Router | Elevation of Privilege | Агент вызывает tool вне разрешённой роли | High | allowlist, schema validation, human approval |
| Tools / APIs / Shell / DB | Tampering | Невалидированные параметры меняют данные или запускают команду | High | parameter validation, sandbox, transaction limits |
| Memory / Vector Store | Tampering | В память сохраняется вредная инструкция | High | memory isolation, memory review, context sanitization |
| Logs / Traces | Information Disclosure | В логах остаются токены, персональные данные, raw prompts | Medium | redaction, log retention, access control |
| Output Validator | Information Disclosure | Ответ раскрывает секреты или внутренние инструкции | High | output filtering, secret scanning, policy check |
| External Agent | Spoofing | Другой агент выдаёт себя за доверенный компонент | Medium | identity, signatures, channel authentication |
| Agent Loop | Denial of Service | Бесконечные шаги, дорогие вызовы, bill spike | Medium | max steps, timeouts, quotas, circuit breaker |
| Audit Logger | Repudiation | Нельзя восстановить, почему агент выполнил действие | Medium | immutable logs, correlation ID, tool call reason |
| Config / Policies | Tampering | Изменение конфигурации расширяет права агента | High | config review, approval, versioning, access control |
| Agent / workflow control plane (exposed) | Elevation of Privilege | ATA (напр. JADEPUFFER): RCE → secrets → pivot → destructive DB | High | auth на control plane, network isolation, no secrets in env, patch, IR playbook §23 |

## Сценарий: Agent Data Injection (spoofed trusted metadata)

Атакующий не пишет «ignore previous instructions». В tool response / документе / issue появляются поля, которые агент привык считать служебными: `document_id`, `source`, `author`, `trusted: true`. Формат валидный JSON → planner или downstream tool использует ID как будто он уже проверен.

| Шаг | Что происходит |
|---|---|
| 1 | Untrusted surface отдаёт structured data с «доверенными» полями |
| 2 | Агент трактует format как trust (или копирует `author`/provenance в audit) |
| 3 | Опасный sink вызывается с подставным resource ID / account / path |

Контрмера на уровне threat model: в DFD пометить **metadata fields внутри untrusted data** как отдельный Tampering/Spoofing путь; controls — policy validation, не «модель разберётся». Канон и checklist — [§03 ADI](../part-2-input-security/03-prompt-injection-detection.md#agent-data-injection-adi).

## Risk Rating

Для этого конспекта достаточно уровней **High / Medium / Low**.

| Уровень | Значение |
|---|---|
| High | Может привести к утечке данных, опасному действию, обходу прав, изменению внешней системы или компрометации |
| Medium | Может привести к ограниченному ущербу, ошибочному действию, DoS, перерасходу бюджета или частичной утечке |
| Low | Локальная ошибка контроля, ухудшение качества, неполный лог, но без прямого критичного ущерба |

Простая матрица:

| Impact / Likelihood | Low | Medium | High |
|---|---|---|---|
| Low | Low | Low | Medium |
| Medium | Low | Medium | High |
| High | Medium | High | High |

## Карта угроз по слоям

| Слой | Основные угрозы | Разделы конспекта |
|---|---|---|
| Вход | prompt injection, indirect injection, PII leakage, token bombing | 03, 04, 05 |
| Обработка | tool misuse, privilege escalation, unsafe parameters, sandbox escape, memory poisoning, secrets exposure | 06, 07, 08, 09, 10 |
| Выход | hallucination, data exfiltration, unsafe response, secret leakage | 11, 12, 13 |
| Контроль | отсутствие approval, плохие логи, отсутствие мониторинга, нет kill-switch | 14, 15, 16, 17 |
| Мультиагентность | spoofing агента, insecure delegation, poisoned inter-agent messages | 18, 19 |
| Практика / compliance | отсутствие red teaming, supply chain, incident response | 20, 21, 22, 23, 24, 25 |
| Инфраструктура агента | exposed control plane, ATA / agentic ransomware | 02 (ATA), 10, 17, 23 |

## Маппинг на OWASP ASI Top 10

OWASP Top 10 for Agentic Applications 2026 можно использовать как внешний справочник рисков для агентных систем.

| OWASP ASI | Риск | Где раскрывать в конспекте |
|---|---|---|
| ASI01 | Agent Goal Hijack | 03 Prompt Injection Detection, 14 Human-in-the-Loop |
| ASI02 | Tool Misuse & Exploitation | 06 RBAC и Tool Permissions, 07 Parameter Validation |
| ASI03 | Identity & Privilege Abuse | 06 RBAC, 10 Secrets Management |
| ASI04 | Agentic Supply Chain Vulnerabilities | 19 MCP Security, 22 Supply Chain Security |
| ASI05 | Unexpected Code Execution | 08 Sandboxing, 07 Schema Enforcement |
| ASI06 | Memory & Context Poisoning | 09 Memory Isolation и Context Sanitization |
| ASI07 | Insecure Inter-Agent Communication | 18 Inter-Agent Security, 19 MCP Security |
| ASI08 | Cascading Failures | 16 Monitoring, 17 Circuit Breaker и Kill-Switch |
| ASI09 | Human-Agent Trust Exploitation | 14 Human-in-the-Loop, 11 Output Validation |
| ASI10 | Rogue Agents | 15 Observability, 16 Monitoring, 17 Kill-Switch |

## Пример (Go)

Иллюстративный риск-реестр. Его можно позже вынести в `pkg/threatmodel/` и сделать runnable-пакетом, но для первой части достаточно snippet'а.

```go
package threatmodel

type Severity string

const (
	High   Severity = "High"
	Medium Severity = "Medium"
	Low    Severity = "Low"
)

type STRIDE string

const (
	Spoofing              STRIDE = "Spoofing"
	Tampering             STRIDE = "Tampering"
	Repudiation           STRIDE = "Repudiation"
	InformationDisclosure STRIDE = "Information Disclosure"
	DenialOfService       STRIDE = "Denial of Service"
	ElevationOfPrivilege  STRIDE = "Elevation of Privilege"
)

type Status string

const (
	Open       Status = "open"
	Mitigated  Status = "mitigated"
	Accepted   Status = "accepted"
	NeedsOwner Status = "needs-owner"
)

type Risk struct {
	ID          string
	DFDElement  string
	Layer       string
	STRIDE      STRIDE
	Scenario    string
	Severity    Severity
	Controls    []string
	Sections    []string
	Status      Status
}

var AgentRisks = []Risk{
	{
		ID:         "R-001",
		DFDElement: "User Input",
		Layer:      "input",
		STRIDE:     Tampering,
		Scenario:   "User prompt attempts to override system instructions or change the agent goal.",
		Severity:   High,
		Controls: []string{
			"prompt injection detection",
			"context isolation",
			"intent validation",
		},
		Sections: []string{"03", "14"},
		Status:   Open,
	},
	{
		ID:         "R-002",
		DFDElement: "Uploaded Docs / Web / Email",
		Layer:      "input",
		STRIDE:     Tampering,
		Scenario:   "Indirect prompt injection hidden in retrieved content influences tool selection.",
		Severity:   High,
		Controls: []string{
			"treat retrieved content as data",
			"content sanitization",
			"tool approval",
		},
		Sections: []string{"03", "09"},
		Status:   Open,
	},
	{
		ID:         "R-003",
		DFDElement: "Tool Router",
		Layer:      "processing",
		STRIDE:     ElevationOfPrivilege,
		Scenario:   "Agent calls a privileged tool outside its allowed role or scope.",
		Severity:   High,
		Controls: []string{
			"RBAC",
			"tool allowlist",
			"schema validation",
			"human approval",
		},
		Sections: []string{"06", "07", "14"},
		Status:   Open,
	},
	{
		ID:         "R-004",
		DFDElement: "Memory / Vector Store",
		Layer:      "processing",
		STRIDE:     Tampering,
		Scenario:   "Malicious instruction is stored in memory and reused in future sessions.",
		Severity:   High,
		Controls: []string{
			"memory isolation",
			"memory write policy",
			"context sanitization",
		},
		Sections: []string{"09"},
		Status:   Open,
	},
	{
		ID:         "R-005",
		DFDElement: "Output Validator",
		Layer:      "output",
		STRIDE:     InformationDisclosure,
		Scenario:   "Final answer exposes secrets, internal prompts, credentials, or private context.",
		Severity:   High,
		Controls: []string{
			"output validation",
			"secret scanning",
			"PII redaction",
		},
		Sections: []string{"04", "11", "13"},
		Status:   Open,
	},
	{
		ID:         "R-006",
		DFDElement: "Agent Loop",
		Layer:      "infrastructure",
		STRIDE:     DenialOfService,
		Scenario:   "Agent repeatedly calls expensive tools or LLM API until quota or budget is exhausted.",
		Severity:   Medium,
		Controls: []string{
			"max steps",
			"timeouts",
			"quotas",
			"circuit breaker",
		},
		Sections: []string{"05", "16", "17"},
		Status:   Open,
	},
}
```

Минимальная проверка риск-реестра:

```go
func HighRisksWithoutControls(risks []Risk) []Risk {
	var result []Risk

	for _, risk := range risks {
		if risk.Severity == High && len(risk.Controls) == 0 {
			result = append(result, risk)
		}
	}

	return result
}
```

Практический смысл:

- risk register можно хранить рядом с кодом;
- можно ревьюить изменения через Git;
- можно тестировать, что у High-рисков есть controls;
- можно связать риски с разделами конспекта и задачами реализации.

## Чек-лист threat modeling

- [ ] Определены активы: данные, инструменты, память, credentials, внешние системы.
- [ ] Определены акторы: пользователь, внешний документ, внешний сервис, другой агент, инсайдер, AI-driven / ATA.
- [ ] Нарисован DFD Level 1.
- [ ] Отмечены trust boundaries.
- [ ] Для каждого внешнего входа указано, почему он недоверенный.
- [ ] Для каждого tool указаны права, scopes и опасные действия.
- [ ] Для каждого data store указано, какие данные там хранятся.
- [ ] STRIDE применён к элементам DFD, а не только списком.
- [ ] Для каждой угрозы указан risk level: High / Medium / Low.
- [ ] Для High-рисков указаны controls.
- [ ] Для опасных tool calls предусмотрен human approval.
- [ ] Для agent loop есть лимиты шагов, времени, стоимости и токенов.
- [ ] Логи не содержат секреты без redaction.
- [ ] Есть связь угроз с разделами конспекта.
- [ ] Учтены exposed AI/agent control planes как initial access для ATA.
- [ ] Есть detection signals для agentic ransomware (self-narrating payloads, rapid retries, credential sweep → destructive).
- [ ] Secrets не предполагаются в env на internet-facing agent hosts.
- [ ] Есть IR playbook на ATA / agentic ransomware ([§23](../part-7-testing-compliance/23-incident-response-recovery.md)).
- [ ] Учтён ADI: spoofed author / resource ID / tool-response metadata не trusted by format ([§03](../part-2-input-security/03-prompt-injection-detection.md#agent-data-injection-adi)).

## Литература

- [Список литературы](../literature.md#стандарты-и-фреймворки)
- [Sysdig — JADEPUFFER: Agentic ransomware for automated database extortion](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion)
- [OWASP Agentic AI — Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Microsoft Learn — Data-flow diagram elements](https://learn.microsoft.com/en-us/training/modules/tm-create-a-threat-model-using-foundational-data-flow-diagram-elements/)
- [NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)

## См. также

- [01 — Введение](01-introduction.md)
- [03 — Prompt Injection Detection](../part-2-input-security/03-prompt-injection-detection.md)
- [06 — RBAC и Tool Permissions](../part-3-processing-security/06-rbac-tool-permissions.md)
- [07 — Parameter Validation и Schema Enforcement](../part-3-processing-security/07-parameter-validation-schema.md)
- [10 — Secrets Management](../part-3-processing-security/10-secrets-management.md)
- [17 — Circuit Breaker и Kill-Switch](../part-5-control-observability/17-circuit-breaker-kill-switch.md)
- [21 — Compliance и Standards](../part-7-testing-compliance/21-compliance-standards.md)
- [23 — Incident Response и Recovery](../part-7-testing-compliance/23-incident-response-recovery.md)
