---
tags: [ai-security, конспект, mapping]
статус: готово
---

# Карта: Тема × Стандарты × Раздел

[← Оглавление](../README.md)

Компактный справочник для навигации «риск → раздел → стандарт». Не заменяет [21 — Compliance и Standards](part-7-testing-compliance/21-compliance-standards.md): там evidence-driven подход, control matrix и примеры на Go.

| Раздел | Тема | OWASP | NIST AI RMF | MITRE ATLAS |
|---|---|---|---|---|
| [01](part-1-architecture-threats/01-introduction.md) | Введение, архитектура агента | ASI Top 10 | Map | — |
| [02](part-1-architecture-threats/02-threat-model.md) | Threat model, STRIDE, risk register | ASI Top 10 | Map | тактики атак на ML |
| [03](part-2-input-security/03-prompt-injection-detection.md) | Prompt injection detection | LLM01, ASI01 | Map, Measure | AML.T0051 |
| [04](part-2-input-security/04-pii-redaction-content-filtering.md) | PII redaction, content filtering | LLM02 | Map, Govern | — |
| [05](part-2-input-security/05-rate-limiting-quotas-token-bombing.md) | Rate limiting, quotas, token bombing | LLM10 | Measure | — |
| [06](part-3-processing-security/06-rbac-tool-permissions.md) | RBAC, tool permissions | ASI02, ASI03 | Map, Govern | — |
| [07](part-3-processing-security/07-parameter-validation-schema.md) | Parameter validation, schema | LLM05 | Map | — |
| [08](part-3-processing-security/08-sandboxing.md) | Sandboxing | ASI05 | Map | — |
| [09](part-3-processing-security/09-memory-isolation-context-sanitization.md) | Memory isolation, context sanitization | ASI06 | Map | AML.T0058 |
| [10](part-3-processing-security/10-secrets-management.md) | Secrets management | LLM02, SSDF | Govern, Map | — |
| [11](part-4-output-security/11-output-validation-fact-checking.md) | Output validation, fact-checking | LLM05 | Measure | — |
| [12](part-4-output-security/12-hallucination-detection.md) | Hallucination detection | LLM09 | Measure | — |
| [13](part-4-output-security/13-egress-control-data-exfiltration.md) | Egress control, data exfiltration | LLM02 | Map, Manage | AML.T0054 |
| [14](part-5-control-observability/14-human-in-the-loop.md) | Human-in-the-Loop | ASI09 | Govern, Manage | — |
| [15](part-5-control-observability/15-observability-tracing.md) | Observability, tracing | — | Manage | — |
| [16](part-5-control-observability/16-monitoring-alerting.md) | Monitoring, alerting | — | Measure, Manage | — |
| [17](part-5-control-observability/17-circuit-breaker-kill-switch.md) | Circuit breaker, kill-switch | — | Manage | — |
| [18](part-6-multi-agent-security/18-inter-agent-security.md) | Inter-agent security | ASI07, ASI08 | Map | — |
| [19](part-6-multi-agent-security/19-mcp-security.md) | MCP security, tool poisoning | MCP Top 10, ASI04 | Map | AML.T0051 |
| [20](part-7-testing-compliance/20-red-teaming-adversarial-testing.md) | Red teaming, adversarial testing | — | Measure (TEVV) | тактики ATLAS |
| [21](part-7-testing-compliance/21-compliance-standards.md) | Compliance, standards mapping | LLM, ASI, MCP | Govern, Map, Manage | ATLAS |
| [22](part-7-testing-compliance/22-supply-chain-security.md) | Supply chain, SBOM | ASI04, SSDF | Govern, Map | AML.T0010 |
| [23](part-7-testing-compliance/23-incident-response-recovery.md) | Incident response, recovery | — | Manage | — |
| [24](part-8-practice/24-end-to-end-secure-agent-go.md) | End-to-end secure agent (Go) | ASI02, ASI05 | Map, Manage | — |
| [25](part-8-practice/25-security-by-design-checklist.md) | Security-by-Design checklist | ASI Top 10 | Govern, Manage | — |
| [26](part-9-ai-coding-security/26-ai-coding-agent-threat-model.md) | AI-coding agent threat model | ASI02, ASI03 | Map | тактики ATLAS |
| [27](part-9-ai-coding-security/27-repository-instructions-attack-surface.md) | Repo as instructions | LLM01, ASI01, ASI06 | Map | AML.T0051 |
| [28](part-9-ai-coding-security/28-coding-agent-permissions-sandbox-approval.md) | Permissions, sandbox, approval | ASI02, ASI03, ASI05 | Map, Govern | — |
| [29](part-9-ai-coding-security/29-ai-generated-code-review-spec-driven.md) | Code review, spec-driven, Security Review Agent | ASI09 | Manage | — |
| [30](part-9-ai-coding-security/30-ai-coding-supply-chain.md) | AI coding supply chain | ASI04, SSDF | Govern, Map | AML.T0010 |
| [31](part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md) | CI/CD, MCP, skills, production path | MCP Top 10, ASI04 | Manage | — |
| [32](part-9-ai-coding-security/32-ai-coding-security-checklist.md) | AI coding security checklist | ASI Top 10 | Govern, Manage | — |

Подробности, evidence и control matrix — в [21 — Compliance и Standards](part-7-testing-compliance/21-compliance-standards.md).

## Литература

- [Список литературы](literature.md#стандарты-и-фреймворки)

## См. также

- [02 — Модель угроз](part-1-architecture-threats/02-threat-model.md)
- [21 — Compliance и Standards](part-7-testing-compliance/21-compliance-standards.md)
