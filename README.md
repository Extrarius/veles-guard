# Безопасность AI-агентов — конспект

Структурированный конспект по безопасности AI-агентов: модель угроз, защита на входе, обработке и выходе, контроль и наблюдаемость, мультиагентная безопасность, тестирование и практика. Примеры кода — на Go.

> Главный принцип: **AI-агент — это недоверенный исполнитель.** Ему нельзя предоставлять лишние права, нельзя смешивать недоверенный контент с управляющими инструкциями, а опасные действия должны идти через sandbox / approval / logging / least privilege.

Защита разбита по слоям: **вход → обработка → выход → инфраструктура**.

## Как читать

- Каждый раздел — отдельная заметка с единой структурой: Суть · Угроза и контекст · Подходы и контрмеры · Пример (Go) · Чек-лист · Литература · См. также.
- Статус: каркас (заглушки `TODO`), наполняется по разделам.
- Шаблон новой заметки: [notes/_template.md](notes/_template.md).
- Все источники: [notes/literature.md](notes/literature.md).

## Оглавление

### Часть I. Архитектура и угрозы
1. [Введение: что такое AI-агент и чем он опасен](notes/part-1-architecture-threats/01-introduction.md)
2. [Модель угроз (Threat Model)](notes/part-1-architecture-threats/02-threat-model.md)

### Часть II. Защита на входе
3. [Prompt Injection Detection](notes/part-2-input-security/03-prompt-injection-detection.md)
4. [PII Redaction и Content Filtering](notes/part-2-input-security/04-pii-redaction-content-filtering.md)
5. [Rate Limiting, Quotas и Token Bombing](notes/part-2-input-security/05-rate-limiting-quotas-token-bombing.md)

### Часть III. Защита обработки
6. [RBAC и Tool Permissions](notes/part-3-processing-security/06-rbac-tool-permissions.md)
7. [Parameter Validation и Schema Enforcement](notes/part-3-processing-security/07-parameter-validation-schema.md)
8. [Sandboxing](notes/part-3-processing-security/08-sandboxing.md)
9. [Memory Isolation и Context Sanitization](notes/part-3-processing-security/09-memory-isolation-context-sanitization.md)
10. [Secrets Management](notes/part-3-processing-security/10-secrets-management.md)

### Часть IV. Защита на выходе
11. [Output Validation и Fact-Checking](notes/part-4-output-security/11-output-validation-fact-checking.md)
12. [Hallucination Detection](notes/part-4-output-security/12-hallucination-detection.md)
13. [Egress Control и Data Exfiltration Prevention](notes/part-4-output-security/13-egress-control-data-exfiltration.md)

### Часть V. Контроль и наблюдаемость
14. [Human-in-the-Loop](notes/part-5-control-observability/14-human-in-the-loop.md)
15. [Observability и Tracing](notes/part-5-control-observability/15-observability-tracing.md)
16. [Monitoring и Alerting](notes/part-5-control-observability/16-monitoring-alerting.md)
17. [Circuit Breaker и Kill-Switch](notes/part-5-control-observability/17-circuit-breaker-kill-switch.md)

### Часть VI. Мультиагентная безопасность
18. [Inter-Agent Security](notes/part-6-multi-agent-security/18-inter-agent-security.md)
19. [MCP Security](notes/part-6-multi-agent-security/19-mcp-security.md)

### Часть VII. Тестирование и compliance
20. [Red Teaming и Adversarial Testing](notes/part-7-testing-compliance/20-red-teaming-adversarial-testing.md)
21. [Compliance и Standards](notes/part-7-testing-compliance/21-compliance-standards.md)
22. [Supply Chain Security](notes/part-7-testing-compliance/22-supply-chain-security.md)
23. [Incident Response и Recovery](notes/part-7-testing-compliance/23-incident-response-recovery.md)

### Часть VIII. Практика
24. [End-to-End: безопасный агент на Go](notes/part-8-practice/24-end-to-end-secure-agent-go.md)
25. [Security-by-Design чек-лист](notes/part-8-practice/25-security-by-design-checklist.md)

## Литература

См. [notes/literature.md](notes/literature.md) — академические работы, стандарты (OWASP / NIST / MITRE ATLAS), практические руководства, MCP и инструменты.
