---
tags: [ai-security, agents, checklist, security-by-design, review]
часть: "Часть VIII — Практика"
статус: готово
обновлено: 2026-07-19
изменения: "C-08/C-09: verified CTI/MCP + machine-readable OSCAL evidence; ссылка на §21."
---

# 25 — Security-by-Design чек-лист

> Навигация: [Оглавление](../../README.md) · [← Назад](24-end-to-end-secure-agent-go.md) · [Вперёд →](../part-9-ai-coding-security/26-ai-coding-agent-threat-model.md)

*Кратко: финальный чек-лист для проектирования, ревью и выпуска AI-агента. Его цель — не “закрыть все галочки”, а не пропустить критичные границы доверия, права, tools, данные, egress, тесты и incident response.*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-8/25-security-by-design-checklist.py) ·
> [TypeScript](../../examples/typescript/part-8/25-security-by-design-checklist.ts)

## Как использовать

Чек-лист применяется на трёх этапах:

```text
Design Review → Pre-Release Review → Production Review
```

Минимальная логика:

| Ответ | Значение |
|---|---|
| Yes | контроль реализован и есть evidence |
| Partial | реализовано частично, нужен owner и срок |
| No | контроль отсутствует |
| N/A | неприменимо, причина зафиксирована |

Правило:

> Для production-агента High-risk пункты не должны оставаться в состоянии No без явного risk acceptance.

## Severity

| Severity | Значение |
|---|---|
| High | отсутствие контроля может привести к утечке данных, опасному tool call, обходу прав или компрометации |
| Medium | отсутствие контроля ухудшает управляемость, расследование или устойчивость |
| Low | улучшает качество и зрелость, но не является критичным gate |

## 1. Архитектура и threat model

| ID | Проверка | Severity | Status |
|---|---|---|---|
| A-01 | Есть описание архитектуры агента | High | TODO |
| A-02 | Есть DFD с trust boundaries | High | TODO |
| A-03 | Отличены trusted и untrusted источники данных | High | TODO |
| A-04 | Есть STRIDE или аналогичная модель угроз | High | TODO |
| A-05 | Есть risk register | High | TODO |
| A-06 | Все tools перечислены в inventory | High | TODO |
| A-07 | Все external systems перечислены | Medium | TODO |
| A-08 | Все data stores перечислены | Medium | TODO |
| A-09 | Для каждого high-risk сценария есть mitigation | High | TODO |
| A-10 | Threat model обновляется при добавлении tool/MCP/server | High | TODO |

## 2. Входной слой

| ID | Проверка | Severity | Status |
|---|---|---|---|
| I-01 | Есть input size limit | Medium | TODO |
| I-02 | Есть token/cost limit на вход | Medium | TODO |
| I-03 | Prompt injection рассматривается как основной риск | High | TODO |
| I-04 | Недоверенный контент маркируется явно | High | TODO |
| I-05 | Пользовательский input не смешивается с system instructions | High | TODO |
| I-06 | Документы, веб-страницы и tool outputs считаются untrusted | High | TODO |
| I-07 | Есть PII/secret detection до логирования | High | TODO |
| I-08 | Есть redaction для чувствительных данных | High | TODO |
| I-09 | Есть rate limits по user/tenant/session | Medium | TODO |
| I-10 | Есть защита от token bombing | Medium | TODO |

## 3. Context и memory

| ID | Проверка | Severity | Status |
|---|---|---|---|
| M-01 | Memory разделена по user/tenant | High | TODO |
| M-02 | Memory records имеют source и trust level | High | TODO |
| M-03 | Untrusted memory не становится instruction | High | TODO |
| M-04 | Memory write проходит policy | High | TODO |
| M-05 | Есть TTL / retention для memory | Medium | TODO |
| M-06 | Есть процедура удаления poisoned memory | High | TODO |
| M-07 | Shared memory не даёт cross-tenant leakage | High | TODO |
| M-08 | Tool output перед записью в memory санитизируется | High | TODO |

## 4. LLM planning

| ID | Проверка | Severity | Status |
|---|---|---|---|
| P-01 | LLM output считается данными, а не командой | High | TODO |
| P-02 | Planner возвращает structured output | High | TODO |
| P-03 | Невалидный structured output блокируется | High | TODO |
| P-04 | LLM не видит секреты | High | TODO |
| P-05 | LLM не получает лишний контекст | High | TODO |
| P-06 | Версия prompt фиксируется | Medium | TODO |
| P-07 | Изменение prompt проходит review | Medium | TODO |
| P-08 | Есть тесты на regressions после изменения prompt | Medium | TODO |

## 5. Tools и permissions

| ID | Проверка | Severity | Status |
|---|---|---|---|
| T-01 | Все tools находятся в allowlist | High | TODO |
| T-02 | У каждого tool есть owner | Medium | TODO |
| T-03 | У каждого tool есть risk level | High | TODO |
| T-04 | У каждого tool есть schema | High | TODO |
| T-05 | Все args проходят strict validation | High | TODO |
| T-06 | Лишние поля в args запрещены | High | TODO |
| T-07 | Tool permissions завязаны на role/scope | High | TODO |
| T-08 | High-risk tools требуют approval | High | TODO |
| T-09 | Destructive tools имеют dry-run или manual mode | High | TODO |
| T-10 | Unknown tool блокируется | High | TODO |
| T-11 | Tool output считается untrusted | High | TODO |
| T-12 | Tool call логируется с run_id | Medium | TODO |

## 6. Sandbox и execution

| ID | Проверка | Severity | Status |
|---|---|---|---|
| S-01 | Shell/code execution запрещён по умолчанию | High | TODO |
| S-02 | Shell/code execution запускается только в sandbox | High | TODO |
| S-03 | Sandbox имеет timeout | High | TODO |
| S-04 | Sandbox имеет filesystem limits | High | TODO |
| S-05 | Sandbox имеет network limits | High | TODO |
| S-06 | Path traversal блокируется | High | TODO |
| S-07 | Command args не собираются через string concatenation | High | TODO |
| S-08 | Dangerous syscalls/capabilities ограничены, где применимо | Medium | TODO |
| S-09 | Ошибки sandbox логируются | Medium | TODO |

## 7. Secrets

| ID | Проверка | Severity | Status |
|---|---|---|---|
| SEC-01 | Секреты не хранятся в prompt | High | TODO |
| SEC-02 | Секреты не передаются в LLM context | High | TODO |
| SEC-03 | Секреты injected server-side только в executor | High | TODO |
| SEC-04 | Секреты redacted в логах | High | TODO |
| SEC-05 | Есть secret scanning в CI | High | TODO |
| SEC-06 | Tokens имеют минимальные scopes | High | TODO |
| SEC-07 | Есть rotation procedure | High | TODO |
| SEC-08 | Есть response plan для secret exposure | High | TODO |

## 8. Egress и data exfiltration

| ID | Проверка | Severity | Status |
|---|---|---|---|
| E-01 | Egress запрещён по умолчанию или ограничен allowlist | High | TODO |
| E-02 | URL проходит validation | High | TODO |
| E-03 | Redirects контролируются | High | TODO |
| E-04 | Private IP ranges блокируются, если не нужны | High | TODO |
| E-05 | Данные перед отправкой проверяются на PII/secrets | High | TODO |
| E-06 | Upload limits включены | Medium | TODO |
| E-07 | Egress events логируются | Medium | TODO |
| E-08 | Egress blocked вызывает alert для high-risk | High | TODO |
| E-09 | MCP/tools не обходят egress policy | High | TODO |

## 9. Output validation

| ID | Проверка | Severity | Status |
|---|---|---|---|
| O-01 | Output считается untrusted | High | TODO |
| O-02 | Output проверяется на secrets/PII | High | TODO |
| O-03 | HTML/Markdown rendering безопасен | High | TODO |
| O-04 | Structured output валидируется | High | TODO |
| O-05 | Ссылки и external destinations проверяются | Medium | TODO |
| O-06 | Фактические утверждения проверяются, где нужно | Medium | TODO |
| O-07 | Неподтверждённые утверждения маркируются | Medium | TODO |
| O-08 | Output guard failures логируются | Medium | TODO |

## 10. Human-in-the-Loop

| ID | Проверка | Severity | Status |
|---|---|---|---|
| H-01 | Approval требуется для high-risk actions | High | TODO |
| H-02 | Approval показывает реальные tool args | High | TODO |
| H-03 | Approval показывает risk и reason | Medium | TODO |
| H-04 | Approval decision логируется | High | TODO |
| H-05 | Rejected action не выполняется | High | TODO |
| H-06 | Approval timeout безопасно блокирует действие | High | TODO |
| H-07 | Нет auto-approval для destructive actions | High | TODO |
| H-08 | Critical actions требуют second approval или manual execution | Medium | TODO |

## 11. Observability

| ID | Проверка | Severity | Status |
|---|---|---|---|
| OBS-01 | У каждого run есть run_id | High | TODO |
| OBS-02 | Tool calls связаны с trace | Medium | TODO |
| OBS-03 | Policy decisions логируются | High | TODO |
| OBS-04 | Denied actions логируются | High | TODO |
| OBS-05 | Approval decisions логируются | High | TODO |
| OBS-06 | Logs проходят redaction | High | TODO |
| OBS-07 | Logs защищены от обычного пользователя агента | High | TODO |
| OBS-08 | Есть retention policy | Medium | TODO |
| OBS-09 | Есть метрики по guardrails failures | Medium | TODO |
| OBS-10 | Есть drilldown от alert к trace | Medium | TODO |

## 12. Monitoring и response controls

| ID | Проверка | Severity | Status |
|---|---|---|---|
| R-01 | Есть alert на egress blocked | High | TODO |
| R-02 | Есть alert на secret detected | High | TODO |
| R-03 | Есть alert на repeated tool_denied | Medium | TODO |
| R-04 | Есть alert на prompt injection spike | Medium | TODO |
| R-05 | Есть max steps для agent loop | High | TODO |
| R-06 | Есть max tool calls | High | TODO |
| R-07 | Есть token/cost budget | Medium | TODO |
| R-08 | Есть circuit breaker per tool | Medium | TODO |
| R-09 | Есть kill-switch вне контроля LLM | High | TODO |
| R-10 | Есть read-only/degraded mode | Medium | TODO |

## 13. Multi-agent

| ID | Проверка | Severity | Status |
|---|---|---|---|
| MA-01 | У каждого агента есть identity | High | TODO |
| MA-02 | У каждого агента есть role/scopes | High | TODO |
| MA-03 | Handoff проходит через policy | High | TODO |
| MA-04 | Delegated scopes ограничены задачей | High | TODO |
| MA-05 | Inter-agent messages имеют provenance | High | TODO |
| MA-06 | Agent output не считается trusted instruction | High | TODO |
| MA-07 | Shared memory изолирована | High | TODO |
| MA-08 | Есть budget на handoffs/depth | Medium | TODO |
| MA-09 | High-risk result проверяется verifier/reviewer | Medium | TODO |

## 14. MCP

| ID | Проверка | Severity | Status |
|---|---|---|---|
| MCP-01 | MCP servers находятся в allowlist | High | TODO |
| MCP-02 | У MCP server есть owner/review status | High | TODO |
| MCP-03 | Tool discovery не даёт автоматического доступа | High | TODO |
| MCP-04 | Tool metadata не считается policy | High | TODO |
| MCP-05 | MCP tools проходят schema validation | High | TODO |
| MCP-06 | MCP sessions изолированы по user/tenant | High | TODO |
| MCP-07 | OAuth tokens не попадают в model context | High | TODO |
| MCP-08 | MCP server не обходит egress policy | High | TODO |
| MCP-09 | Command execution MCP tools работают только в sandbox | High | TODO |
| MCP-10 | Есть kill-switch per MCP server | High | TODO |

## 15. Testing и red teaming

| ID | Проверка | Severity | Status |
|---|---|---|---|
| RT-01 | Есть red team test cases | High | TODO |
| RT-02 | Есть prompt injection tests | High | TODO |
| RT-03 | Есть data exfiltration tests | High | TODO |
| RT-04 | Есть tool misuse tests | High | TODO |
| RT-05 | Есть memory poisoning tests | High | TODO |
| RT-06 | Есть egress bypass tests | High | TODO |
| RT-07 | Есть runaway loop tests | Medium | TODO |
| RT-08 | Tests проверяют tool calls, а не только final answer | High | TODO |
| RT-09 | Red team findings превращаются в regression tests | High | TODO |
| RT-10 | High-risk regression failure блокирует release | High | TODO |

Слои security evals (code-based / LLM-as-judge / human / online) и правило «критичное — до релиза» — в [20 — Типы evals для AI-agent security](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md#типы-evals-для-ai-agent-security).

## 16. Supply chain

| ID | Проверка | Severity | Status |
|---|---|---|---|
| SC-01 | Dependencies pinned | Medium | TODO |
| SC-02 | Container images pinned by digest | Medium | TODO |
| SC-03 | Есть SBOM | Medium | TODO |
| SC-04 | Есть dependency scanning | High | TODO |
| SC-05 | Есть secret scanning | High | TODO |
| SC-06 | Prompts versioned | Medium | TODO |
| SC-07 | Policies versioned | Medium | TODO |
| SC-08 | Tool schemas versioned | Medium | TODO |
| SC-09 | Новый tool требует review | High | TODO |
| SC-10 | Новый MCP server требует review | High | TODO |
| SC-11 | Model version фиксируется | Medium | TODO |
| SC-12 | Eval datasets versioned | Low | TODO |

## 17. Compliance и evidence

| ID | Проверка | Severity | Status |
|---|---|---|---|
| C-01 | Controls связаны с OWASP/NIST/MITRE, где применимо | Medium | TODO |
| C-02 | У каждого high-risk control есть owner | High | TODO |
| C-03 | Implemented control имеет evidence | Medium | TODO |
| C-04 | Exceptions имеют owner и expiration date | Medium | TODO |
| C-05 | Privacy risks рассмотрены отдельно | High | TODO |
| C-06 | Logs/traces достаточны для расследования | High | TODO |
| C-07 | Risk register обновляется перед release | High | TODO |
| C-08 | Vuln/CTI claims для compliance не из «памяти модели» — только verified tool/MCP + schema/policy ([§21](../part-7-testing-compliance/21-compliance-standards.md#case-study-mcp--knowledge-graph--nist-oscal)) | High | TODO |
| C-09 | Audit evidence machine-readable (OSCAL SSP/SAR или эквивалент), где применимо; extraction из NL docs — human review | Medium | TODO |

## 18. Incident response

| ID | Проверка | Severity | Status |
|---|---|---|---|
| IR-01 | Есть severity matrix | Medium | TODO |
| IR-02 | Есть owner incident response | High | TODO |
| IR-03 | Есть playbook для prompt injection | High | TODO |
| IR-04 | Есть playbook для secret exposure | High | TODO |
| IR-05 | Есть playbook для MCP compromise | High | TODO |
| IR-06 | Есть rollback prompt/policy/model/tool | High | TODO |
| IR-07 | Есть secret rotation procedure | High | TODO |
| IR-08 | Есть процедура очистки poisoned memory | High | TODO |
| IR-09 | Postmortem обновляет threat model | Medium | TODO |
| IR-10 | Postmortem обновляет tests/monitoring | Medium | TODO |

## 19. AI Coding / SDD

| ID | Проверка | Severity | Status |
|---|---|---|---|
| AC-01 | Generated code review перед commit/merge | High | TODO |
| AC-02 | `AGENTS.md` / `.cursor/rules` / skills версионируются и ревьюятся | High | TODO |
| AC-03 | Spec/proposal одобрен до того, как агент пишет код | Medium | TODO |
| AC-04 | Coding agent не имеет лишних прав в репозитории | High | TODO |
| AC-05 | Агент не может отключать security checks в diff | High | TODO |

Подробный AI-coding чек-лист — в [32 — AI Coding Security Checklist](../part-9-ai-coding-security/32-ai-coding-security-checklist.md).

## Production gate

Минимальный gate перед production:

```text
BLOCK release if:
- нет DFD/threat model;
- high-risk tools без approval;
- нет schema validation;
- egress unrestricted;
- secrets могут попасть в LLM context;
- нет audit logs для tool calls;
- нет kill-switch;
- high-risk red team test failed;
- новый MCP server без review;
- нет incident response owner;
- generated code попал в production без review.
```

## Пример машинно-читаемого checklist item

```json
{
  "id": "T-05",
  "title": "All tool args pass strict validation",
  "severity": "High",
  "status": "Yes",
  "evidence": [
    "internal/tools/schema.go",
    "redteam/RT-003-schema-bypass"
  ],
  "owner": "agent-runtime",
  "review_date": "2026-06-07"
}
```

## Пример валидатора checklist на Go

```go
package checklist

import (
	"encoding/json"
	"errors"
	"time"
)

type Severity string
type Status string

const (
	High   Severity = "High"
	Medium Severity = "Medium"
	Low    Severity = "Low"

	Yes     Status = "Yes"
	Partial Status = "Partial"
	No      Status = "No"
	NA      Status = "N/A"
)

type Item struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Severity   Severity  `json:"severity"`
	Status     Status    `json:"status"`
	Evidence   []string  `json:"evidence"`
	Owner      string    `json:"owner"`
	ReviewDate time.Time `json:"review_date"`
	Reason     string    `json:"reason,omitempty"`
}

func Validate(items []Item) error {
	for _, item := range items {
		if item.ID == "" || item.Title == "" {
			return errors.New("checklist item has required empty fields")
		}

		if item.Severity == "" || item.Status == "" {
			return errors.New("checklist item has no severity or status: " + item.ID)
		}

		if item.Severity == High && item.Status == Yes && len(item.Evidence) == 0 {
			return errors.New("high severity item marked Yes without evidence: " + item.ID)
		}

		if item.Severity == High && item.Status == No {
			return errors.New("high severity item is No and blocks release: " + item.ID)
		}

		if item.Status == Partial && item.Owner == "" {
			return errors.New("partial item has no owner: " + item.ID)
		}

		if item.Status == NA && item.Reason == "" {
			return errors.New("N/A item requires reason: " + item.ID)
		}
	}

	return nil
}

func Export(items []Item) ([]byte, error) {
	if err := Validate(items); err != nil {
		return nil, err
	}

	return json.MarshalIndent(items, "", "  ")
}
```

## Definition of Done

Агент можно считать минимально подготовленным к production, если:

- threat model написан;
- DFD есть;
- high-risk tools требуют approval;
- LLM не выполняет tools напрямую;
- все tool calls проходят policy/schema;
- egress ограничен;
- secrets не попадают в model context;
- output проверяется;
- logs/traces есть;
- kill-switch есть;
- red team suite есть;
- incident playbooks есть.

## Литература

- [Список литературы](../literature.md#стандарты-и-фреймворки)
- [OWASP Securing Agentic Applications Guide 1.0](https://genai.owasp.org/resource/securing-agentic-applications-guide-1-0/)
- [OWASP Agentic AI — Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [OpenAI Agents SDK — Guardrails and Human Review](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals)

## См. также

- [02 — Модель угроз](../part-1-architecture-threats/02-threat-model.md)
- [06 — RBAC и Tool Permissions](../part-3-processing-security/06-rbac-tool-permissions.md)
- [13 — Egress Control и Data Exfiltration Prevention](../part-4-output-security/13-egress-control-data-exfiltration.md)
- [17 — Circuit Breaker и Kill-Switch](../part-5-control-observability/17-circuit-breaker-kill-switch.md)
- [20 — Red Teaming и Adversarial Testing](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md)
- [21 — Compliance: MCP → OSCAL](../part-7-testing-compliance/21-compliance-standards.md#case-study-mcp--knowledge-graph--nist-oscal)
- [24 — End-to-End: безопасный агент на Go](24-end-to-end-secure-agent-go.md)
- [32 — AI Coding Security Checklist](../part-9-ai-coding-security/32-ai-coding-security-checklist.md)
