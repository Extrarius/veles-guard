---
tags: [ai-security, конспект, glossary]
статус: готово
---

# Глоссарий

[← Оглавление](../README.md)

Краткие определения терминов конспекта со ссылками на профильные разделы. Полные объяснения — в самих разделах.

## A

**Agent (AI-агент)** — LLM-исполнитель с доступом к tools, памяти и внешним системам; рассматривается как недоверенный исполнитель. См. [01 — Введение](part-1-architecture-threats/01-introduction.md).

## C

**Circuit Breaker** — механизм остановки опасных или аномальных цепочек вызовов до полного отказа. См. [17 — Circuit Breaker и Kill-Switch](part-5-control-observability/17-circuit-breaker-kill-switch.md).

**Confused deputy** — компонент с избыточными правами выполняет действие от имени атакующего, не понимая истинного намерения. См. [06 — RBAC](part-3-processing-security/06-rbac-tool-permissions.md), [19 — MCP Security](part-6-multi-agent-security/19-mcp-security.md).

## E

**Egress control** — ограничение исходящих данных и сетевых запросов агента (allowlist, DLP). См. [13 — Egress Control](part-4-output-security/13-egress-control-data-exfiltration.md).

## G

**Guardrail** — контроль на входе, в runtime или на выходе, ограничивающий поведение агента (policy, validation, moderation). См. [11 — Output Validation](part-4-output-security/11-output-validation-fact-checking.md), [03 — Prompt Injection](part-2-input-security/03-prompt-injection-detection.md).

## H

**HITL (Human-in-the-Loop)** — обязательное участие человека в approval, review или override опасных действий. См. [14 — Human-in-the-Loop](part-5-control-observability/14-human-in-the-loop.md).

## K

**Kill-switch** — аварийное отключение агента, tool, MCP server или skill при критическом событии. См. [17 — Circuit Breaker и Kill-Switch](part-5-control-observability/17-circuit-breaker-kill-switch.md).

## M

**MCP (Model Context Protocol)** — протокол подключения агента к внешним tools, resources и data sources; расширяет attack surface. См. [19 — MCP Security](part-6-multi-agent-security/19-mcp-security.md).

## O

**Observability** — трассировка, audit logs и метрики для расследования и compliance. См. [15 — Observability и Tracing](part-5-control-observability/15-observability-tracing.md).

## P

**PII Redaction** — удаление или маскирование персональных данных до попадания в LLM, logs или egress. См. [04 — PII Redaction](part-2-input-security/04-pii-redaction-content-filtering.md).

**Prompt Injection** — внедрение управляющих инструкций через недоверенный вход (direct/indirect). См. [03 — Prompt Injection Detection](part-2-input-security/03-prompt-injection-detection.md).

## R

**RBAC (Role-Based Access Control)** — роли и scopes для ограничения доступа агента к tools и данным. См. [06 — RBAC и Tool Permissions](part-3-processing-security/06-rbac-tool-permissions.md).

**Red Teaming** — adversarial-тестирование агента под атакой с превращением findings в regression tests. См. [20 — Red Teaming](part-7-testing-compliance/20-red-teaming-adversarial-testing.md).

**Rug pull** — безопасная версия skill/MCP/модели/пакета заменяется вредной после consent или обновления на `latest`. См. [30 — AI Coding Supply Chain](part-9-ai-coding-security/30-ai-coding-supply-chain.md), [22 — Supply Chain](part-7-testing-compliance/22-supply-chain-security.md).

## S

**Sandbox** — изолированная среда выполнения для shell, filesystem и network tools. См. [08 — Sandboxing](part-3-processing-security/08-sandboxing.md).

**SBOM (Software Bill of Materials)** — перечень зависимостей и артефактов с версиями и hashes. См. [22 — Supply Chain Security](part-7-testing-compliance/22-supply-chain-security.md).

**Secrets Management** — хранение и инъекция секретов без попадания в model context. См. [10 — Secrets Management](part-3-processing-security/10-secrets-management.md).

**Security Review Agent** — AI-reviewer для agent-generated diff/PR; дополняет SAST/DAST, не заменяет их. См. [29 — AI-generated code review](part-9-ai-coding-security/29-ai-generated-code-review-spec-driven.md).

**Skill poisoning** — безопасное `description` skill/plugin при вредном `body` или script. См. [30 — AI Coding Supply Chain](part-9-ai-coding-security/30-ai-coding-supply-chain.md).

**Spec-driven** — фиксация intent/scope/forbidden changes до кода агентом-кодером; контрольная точка безопасности. См. [29 — AI-generated code review](part-9-ai-coding-security/29-ai-generated-code-review-spec-driven.md), [24 — End-to-End](part-8-practice/24-end-to-end-secure-agent-go.md).

**Supply Chain** — контроль зависимостей, моделей, prompts, MCP, skills и CI/CD в цепочке агента. См. [22 — Supply Chain Security](part-7-testing-compliance/22-supply-chain-security.md).

## T

**Tool** — внешняя capability агента (API, shell, DB, file); каждый tool — trust boundary. См. [06 — RBAC](part-3-processing-security/06-rbac-tool-permissions.md).

**Tool Poisoning** — metadata/description MCP tool заставляет агента использовать инструмент не так, как ожидает пользователь. См. [19 — MCP Security](part-6-multi-agent-security/19-mcp-security.md).

## См. также

- [Оглавление](../README.md)
- [Список литературы](literature.md)
- [Карта стандартов](mapping.md)
