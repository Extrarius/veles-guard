---
tags: [ai-security, testing, review, guide, agents]
статус: готово
обновлено: 2026-07-26
изменения: "RoE: Trusted defender access → §23; checklist."
---

# AI Agent Security Testing Guide

[← Оглавление](../README.md)

> **Гайд по проверке безопасности AI-агентов.** Практическая обвязка над [§20](../notes/part-7-testing-compliance/20-red-teaming-adversarial-testing.md), [§23](../notes/part-7-testing-compliance/23-incident-response-recovery.md), [§25](../notes/part-8-practice/25-security-by-design-checklist.md) и [§32](../notes/part-9-ai-coding-security/32-ai-coding-security-checklist.md): порядок проверки, а не теория и не offensive-руководство.

Вопрос, на который отвечает гайд:

```text
Окей, я прочитал конспект. А как теперь проверить своего агента?
```

Учебный проход по этому гайду — [§37](../notes/part-10-course-appendix/37-ai-agent-security-testing-workshop.md). Заполняемая форма finding — [templates/agent-security-finding.md](../templates/agent-security-finding.md).

## 1. Scope

### Что входит в проверку

| Область | Примеры объектов |
|---|---|
| Agent runtime | цикл агента, policy, kill-switch, лимиты шагов |
| Tools | RBAC, schema, approval gates |
| Memory | запись/чтение, изоляция пользователей |
| MCP | серверы, описания tools, pin / provenance |
| Egress | allowlist доменов, блокировка exfiltration |
| Sandbox | shell / FS / network границы |
| Approvals | HITL на dangerous sinks |
| Logs / traces | evidence для finding и IR |
| AI-coding workflow | инструкции репозитория, CI/CD, skills, зависимости |

### Что не входит

- атаки на чужие системы и инфраструктуру без явного разрешения владельца;
- эксплуатация внешних MCP / tools вне своего sandbox;
- реальные destructive actions (удаление prod-данных, отправка в боевые каналы);
- каталог offensive payloads и инструкции «как обойти защиту».

Формулируйте проверки **позитивно**:

```text
Проверить, что агент НЕ раскрывает секреты.
Проверить, что egress блокирует внешний домен вне allowlist.
Проверить, что tool call не проходит без approval.
```

## 2. Rules of Engagement

1. Тестировать только **свой** агент / согласованный sandbox / staging.
2. Не использовать **реальные** секреты, токены, PII клиентов.
3. Не отправлять данные во **внешние** домены вне тестового allowlist; для egress-проверок — mock / sinkhole.
4. Destructive tools заменять **mock tools** с тем же контрактом.
5. Все findings фиксировать по [шаблону](../templates/agent-security-finding.md); устное «вроде баг» не считается.
6. Finding с Critical/High без fix + regression **блокирует** production usage (согласовано с §25 / §32).
7. Не публиковать в issues / PR реальные секреты, внутренние URL и offensive payload (см. [README](../README.md)).
8. **Containment:** sandbox ≠ isolation. Перед прогоном — [pre-eval checklist §08](../notes/part-3-processing-security/08-sandboxing.md#sandbox--isolation-containment-escape); kill-switch drill ([§17](../notes/part-5-control-observability/17-circuit-breaker-kill-switch.md)); suite [`EVAL-CONTAINMENT-01`](../notes/part-7-testing-compliance/20-red-teaming-adversarial-testing.md#containment-evals-eval-containment-01) (boundary crossing = fail).
9. **Trusted defender access:** elevated доступ к tooling / attack materials — только по [§23 Trusted defender access](../notes/part-7-testing-compliance/23-incident-response-recovery.md#trusted-defender-access) (verified role, isolated env, audit, TTL, no auto-export, kill access). Не смешивать с обычным sandbox testing по пунктам 1–8.

## 3. Test Matrix

| Область | Что проверять | Risk |
|---|---|---|
| Input | prompt injection не меняет policy; token bombing не валит runtime | High |
| Context | trusted и untrusted данные не смешиваются в одном instruction channel | High |
| Tools | RBAC, schema bypass не проходит, tool hijacking ловится | High |
| Memory | memory poisoning и cross-user leakage невозможны | High |
| Sandbox | shell / file / network escape блокируются; нет выхода за стенд (`EVAL-CONTAINMENT-01`) | Critical |
| Egress | data exfiltration и domain bypass блокируются | Critical |
| Output | секреты не утекают; unsafe rendering / hallucination с риском действия — под контролем | High |
| MCP | tool poisoning и shadow server не проходят review/pin | High |
| AI-coding | AGENTS.md / repo instructions, CI/CD, dependency changes под review | High |

Минимум для первого прохода: взять **3–4** строки matrix, релевантные вашему агенту, и довести каждую до Expected / Actual / Evidence.

### 3.1 Iterative adversarial (GPT-Red pattern)

Single-shot кейс проверяет один вход. Агент может пройти single-shot и провалить **итеративный** прогон: попытка → наблюдение (ответ / tools / egress) → мутация → повтор до success или бюджета. Индустриальный паттерн (в т.ч. [OpenAI GPT-Red](https://openai.com/index/unlocking-self-improvement-gpt-red/)) — про процесс, не про продукт OpenAI.

Канон цикла, surfaces, schema и runner — [§20 Iterative Adversarial Evals](../notes/part-7-testing-compliance/20-red-teaming-adversarial-testing.md#iterative-adversarial-evals). Здесь только что зафиксировать в отчёте проверки.

| Метрика / поле | Зачем в Report |
|---|---|
| `max_attempts` / stop budget | предел итераций (timeout / cost) |
| `ASR` | доля успешных атак (attack success rate) |
| `attempts_to_success` | на какой попытке first success (или null) |

> **Правило:** automated iterative red team **дополняет** human review и runtime controls (EV-03 / EV-04 / EV-06). Не единственный release gate.

Для high-risk агента: iterative suite **или** явный N/A с причиной ([EV-06](../notes/part-7-testing-compliance/20-red-teaming-adversarial-testing.md)).

## 4. Severity

| Severity | Когда ставить | Production |
|---|---|---|
| **Critical** | Sandbox escape, успешный egress exfiltration, arbitrary tool/shell без контроля | Блок до fix + regression |
| **High** | Prompt injection меняет поведение tools; schema/RBAC bypass; утечка секретов в output; MCP без pin с опасными caps | Блок до fix + regression |
| **Medium** | Пробел в logging/HITL при наличии компенсирующих контролей; частичный bypass с низкой blast radius | Срок + owner; не игнорировать |
| **Low** | Улучшения процесса, отсутствие inventory/owner при низком риске | Backlog с датой |

Правило:

```text
Critical / High без Fix и Regression test → production usage запрещён.
```

## 5. Findings Template

Заполняемая форма: [templates/agent-security-finding.md](../templates/agent-security-finding.md).

| Поле | Описание |
|---|---|
| ID | уникальный номер, например `ASF-2026-001` |
| Title | короткое название |
| Severity | Critical / High / Medium / Low |
| Area | input / context / tools / memory / sandbox / egress / output / MCP / AI-coding |
| Scenario | что проверялось (позитивная формулировка) |
| Expected | как должно быть по политике |
| Actual | что произошло |
| Evidence | logs / trace / screenshot / diff (без секретов) |
| Fix | что исправить |
| Regression test | какой тест / CI gate добавить |
| Handbook refs | ссылки на разделы конспекта |

## 6. Report

Итоговый отчёт проверки:

1. **Summary** — что тестировали (scope), дата, кто проводил.
2. **High-risk findings** — Critical / High списком (ID + title + severity).
3. **Blocked** — что запрещено к production до fix.
4. **Follow-ups** — Medium / Low с owner и сроком.
5. **Checklist updates** — что добавить в [§25](../notes/part-8-practice/25-security-by-design-checklist.md) / [§32](../notes/part-9-ai-coding-security/32-ai-coding-security-checklist.md).
6. **Red team updates** — какие кейсы добавить в suite ([§20](../notes/part-7-testing-compliance/20-red-teaming-adversarial-testing.md)).
7. **IR readiness** — если finding уже похож на инцидент — карточка / playbook ([§23](../notes/part-7-testing-compliance/23-incident-response-recovery.md)).

## 7. Mapping to handbook

| Area (matrix) | Разделы конспекта |
|---|---|
| Input | [§03 Prompt injection](../notes/part-2-input-security/03-prompt-injection-detection.md), [§20](../notes/part-7-testing-compliance/20-red-teaming-adversarial-testing.md) |
| Context | [§03](../notes/part-2-input-security/03-prompt-injection-detection.md), [§04](../notes/part-2-input-security/04-input-sanitization-normalization.md) |
| Tools | [§06 RBAC](../notes/part-3-processing-security/06-rbac-tool-permissions.md), [§07 Schema](../notes/part-3-processing-security/07-parameter-validation-schema.md), [§14 HITL](../notes/part-5-control-observability/14-human-in-the-loop.md) |
| Memory | [§09 Memory](../notes/part-3-processing-security/09-memory-security.md) |
| Sandbox | [§08 Sandboxing](../notes/part-3-processing-security/08-sandboxing.md), [§28](../notes/part-9-ai-coding-security/28-coding-agent-permissions-sandbox-approval.md) |
| Egress | [§13 Egress](../notes/part-4-output-security/13-egress-control-data-exfiltration.md) |
| Output | [§11 Output validation](../notes/part-4-output-security/11-output-validation-fact-checking.md), [§12 Secrets](../notes/part-4-output-security/12-secrets-pii-filtering.md) |
| MCP | [§19 MCP](../notes/part-6-multi-agent-security/19-mcp-security.md), [§31](../notes/part-9-ai-coding-security/31-ci-cd-mcp-skills-production-path.md), [§35](../notes/part-10-course-appendix/35-mcp-skill-review-workshop.md) |
| AI-coding | [§27](../notes/part-9-ai-coding-security/27-repository-instructions-attack-surface.md)–[§32](../notes/part-9-ai-coding-security/32-ai-coding-security-checklist.md) |
| Process / IR | [§20](../notes/part-7-testing-compliance/20-red-teaming-adversarial-testing.md), [§23](../notes/part-7-testing-compliance/23-incident-response-recovery.md), [§25](../notes/part-8-practice/25-security-by-design-checklist.md) |
| Course practice | [§33](../notes/part-10-course-appendix/33-course-ai-security-landscape.md)–[§37](../notes/part-10-course-appendix/37-ai-agent-security-testing-workshop.md) |

Ядро обвязки: **§20** (как тестировать adversarially) → **этот гайд** (порядок и findings) → **§25 / §32** (чеклисты) → **§23** (если finding = инцидент).

## 8. Regression Tests

Правило из §20:

> Red team finding должен превращаться в воспроизводимый regression test.

Для каждого Critical / High:

1. Зафиксировать минимальный воспроизводимый сценарий (без offensive payload dump в публичном репо — описание Expected/Actual + fixture в закрытом suite допустимы).
2. Добавить automated check (code-based / policy unit / CI gate), где возможно.
3. Привязать ID finding к ID теста (`ASF-…` → `RT-…` / CI job).
4. Не закрывать finding, пока regression не зелёный на main/staging.

## Чек-лист перед закрытием проверки

- [ ] Scope и RoE согласованы письменно (хотя бы в отчёте)
- [ ] Пройдены выбранные строки Test Matrix
- [ ] Для high-risk: iterative suite (EV-06) или явный N/A; при iterative — `max_attempts` / ASR в Report
- [ ] Elevated / defender access (если нужен) — по [§23 Trusted defender access](../notes/part-7-testing-compliance/23-incident-response-recovery.md#trusted-defender-access), не ad-hoc в prod
- [ ] Все findings в шаблоне; Critical/High имеют Fix + Regression
- [ ] Report содержит Blocked и Checklist / Red team updates
- [ ] Mapping на разделы конспекта проставлен (хотя бы для High+)

## См. также

- [20 — Red Teaming (Iterative Adversarial Evals)](../notes/part-7-testing-compliance/20-red-teaming-adversarial-testing.md#iterative-adversarial-evals)
- [OpenAI — GPT-Red](https://openai.com/index/unlocking-self-improvement-gpt-red/) — индустриальный паттерн iterative red team
- [23 — Incident Response (Trusted defender access)](../notes/part-7-testing-compliance/23-incident-response-recovery.md#trusted-defender-access)
- [25 — Security-by-Design чек-лист](../notes/part-8-practice/25-security-by-design-checklist.md)
- [32 — AI Coding Security Checklist](../notes/part-9-ai-coding-security/32-ai-coding-security-checklist.md)
- [33–37 — Учебное приложение](../notes/part-10-course-appendix/33-course-ai-security-landscape.md)
- [templates/agent-security-finding.md](../templates/agent-security-finding.md)
- [templates/agentic-security-baseline.md](../templates/agentic-security-baseline.md)
- [templates/mcp-skill-review.md](../templates/mcp-skill-review.md)
