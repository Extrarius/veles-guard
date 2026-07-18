# AI Agent Security Handbook

**Практический справочник по безопасности AI-агентов.** Структурированный справочник: модель угроз, защита на входе, обработке и выходе, контроль и наблюдаемость, мультиагентная безопасность, тестирование и практика. Примеры кода — на Go (иллюстративные).

Защита разбита по слоям: **вход → обработка → выход → инфраструктура**.

## Зачем этот справочник

AI-агенты перестают быть «чатом с моделью»: они получают инструменты, память и доступ к файлам, API, shell, MCP-серверам, репозиториям и CI/CD. Агент уже не только отвечает текстом — он выполняет действия в реальной системе.

Из-за этого меняется модель риска: обычная LLM ошибается **ответом**, агент — **действием** (вызвать не тот инструмент, отправить данные наружу, выполнить команду, раскрыть секрет, принять недоверенный текст за инструкцию).

Та же логика работает и в обратную сторону: атакующие всё чаще автоматизируют разведку, эксплуатацию и перемещение по сети с помощью агентов — это уже задокументировано в отчётах threat intelligence. Поэтому threat model нужно строить с учётом не только защиты своего агента, но и того, что противник может применять похожие возможности против вашего продукта и инфраструктуры.

Справочник раскладывает безопасность агента по слоям: что защищаем, где проходят границы доверия, какие угрозы появляются на входе, в обработке, на выходе и в инфраструктуре, как ограничивать инструменты, память, права и egress, как тестировать агента и расследовать инциденты, как безопасно использовать AI-coding, MCP и agent skills.

Справочник пригодится, если нужно:

- построить агента с доступом к tools/API или подключить MCP-серверы;
- безопасно использовать AI-coding workflow (Cursor / Claude Code / Codex / Copilot Agent);
- дать агенту доступ к коду, базе данных, файлам, shell или CI/CD;
- определить, какие действия требуют human approval;
- подготовить threat model, чек-лист или security review перед запуском.

> Главный принцип: **AI-агент — это недоверенный исполнитель.** Ему нельзя предоставлять лишние права, нельзя смешивать недоверенный контент с управляющими инструкциями, а опасные действия должны идти через policy, sandbox, approval, logging и least privilege.

Справочник не претендует на роль стандарта и не заменяет OWASP / NIST / MITRE ATLAS. Это практическая карта тем, угроз и защитных подходов — основа для проектирования, ревью и развития собственных AI-агентов.

Коротко:

- OWASP — что может пойти не так.
- NIST AI RMF — как управлять рисками системно.
- MITRE ATLAS — какие техники атак на AI-системы уже описаны.

## Для кого

- backend-разработчики, которые добавляют LLM/tools в свои сервисы;
- разработчики AI-агентов и пользователи AI-coding (Cursor / Codex / Claude Code / Copilot);
- DevOps / security-инженеры, которым нужно оценивать риски MCP, CI/CD и supply chain;
- те, кому нужно собрать threat model или чек-лист для AI-системы.

## Как читать

- Каждый раздел — отдельная заметка с единой структурой: Суть · Угроза и контекст · Подходы и контрмеры · Пример (Go) · Чек-лист · Литература · См. также.
- Разделы 01–35: статус готово.
- Шаблон новой заметки: [notes/_template.md](notes/_template.md).
- Все источники: [notes/literature.md](notes/literature.md).
- Карта стандартов: [notes/mapping.md](notes/mapping.md).
- Глоссарий: [notes/glossary.md](notes/glossary.md).
- Рабочие шаблоны (threat model, risk register, tool/MCP review, agentic security baseline, MCP/Skill review, incident report): [templates/](templates/).

## Версионирование разделов

Разделы несут в frontmatter поля `обновлено` (дата) и `изменения` (краткое описание правки) — для отслеживания эволюции при чтении в Obsidian без git log. При правке раздела обновляйте оба поля; в новых заметках — по [notes/_template.md](notes/_template.md).

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

### Часть IX. AI Coding Agent Security
26. [AI-coding agent: модель угроз](notes/part-9-ai-coding-security/26-ai-coding-agent-threat-model.md)
27. [Репозиторий как источник инструкций](notes/part-9-ai-coding-security/27-repository-instructions-attack-surface.md)
28. [Permissions, sandbox и approval для coding agents](notes/part-9-ai-coding-security/28-coding-agent-permissions-sandbox-approval.md)
29. [AI-generated code review и spec-driven workflow](notes/part-9-ai-coding-security/29-ai-generated-code-review-spec-driven.md)
30. [AI Coding Supply Chain](notes/part-9-ai-coding-security/30-ai-coding-supply-chain.md)
31. [CI/CD, MCP, Skills и production path](notes/part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md)
32. [AI Coding Security Checklist](notes/part-9-ai-coding-security/32-ai-coding-security-checklist.md)

### Часть X. Учебное приложение
33. [Course Appendix: практикум MCP / Skills](notes/part-10-course-appendix/33-course-appendix-agentic-security.md)
34. [MCP / Skill Review Workshop](notes/part-10-course-appendix/34-mcp-skill-review-workshop.md)
35. [Agentic Security Baseline Workshop](notes/part-10-course-appendix/35-agentic-security-baseline-workshop.md)

### Учебное приложение

Отдельный прикладной блок для курсов, воркшопов и внутренних разборов.
Содержит шаблоны, baseline-подходы и безопасные учебные примеры для ревью MCP,
agent skills и AI-coding workflow. См. также [templates/course/](templates/course/) и [examples/course/](examples/course/).

## Литература

См. [notes/literature.md](notes/literature.md) — академические работы, стандарты (OWASP / NIST / MITRE ATLAS), практические руководства, MCP и инструменты.

## Благодарности

Благодарю ТД «Система» за возможность пройти путь от первых практических ошибок до работающего результата. Опыт решения реальных задач стал одной из отправных точек для появления этого справочника.

Отдельная благодарность Эдгару Сипки за совместные обсуждения, которые помогли сформулировать важную мысль: «хороший разработчик» не равно «специалист по безопасности». Эти разговоры, а также его курс [«LLM в продакшене»](https://ai.courses.sipki.tech/), повлияли на мой взгляд в эксплуатации LLM-систем и стали одним из импульсов для появления части IX — AI Coding Agent Security.

## Обратная связь и вопросы

Исправления, предложения и вопросы — через [GitHub Issues](https://github.com/Extrarius/veles-guard/issues). Доступные шаблоны:

- **Correction** — фактические ошибки, формулировки, битые ссылки;
- **Suggestion** — новые темы или улучшения структуры;
- **Question** — вопросы по материалам справочника.

Пожалуйста, не публикуйте реальные секреты, токены, внутренние URL или offensive payload.

## License

Documentation, notes, checklists and templates are licensed under **[CC BY 4.0](DOCS-LICENSE.md)**.

Code examples are licensed under the **[MIT License](LICENSE)**.

You are free to use, share and adapt the materials with attribution.

## Project status

This project is maintained as a curated security handbook.

External contributions are welcome as [issues](https://github.com/Extrarius/veles-guard/issues) or pull requests, but all changes are reviewed manually. Because the topic touches AI security, agent tooling, MCP, supply chain and offensive testing scenarios, maintainers may reject changes that are unsafe, poorly sourced or too operationally offensive.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
