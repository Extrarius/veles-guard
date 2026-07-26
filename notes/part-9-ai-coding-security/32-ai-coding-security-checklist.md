---
tags: [ai-security, ai-coding, checklist, production-review]
часть: "Часть IX — AI Coding Agent Security"
статус: готово
обновлено: 2026-07-19
изменения: "AC-ADI-01/02: resource IDs / self-asserted trust из tool/issue/PR; ссылка на §03."
---

# 32 — AI Coding Security Checklist

> Навигация: [Оглавление](../../README.md) · [← Назад](31-ci-cd-mcp-skills-production-path.md) · [Вперёд →](../part-10-course-appendix/33-course-appendix-agentic-security.md)

*Кратко: итоговый checklist для безопасной работы с AI-coding agents: repo instructions, permissions, sandbox, review, supply chain, CI/CD, MCP, skills, secrets и incident response.*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-9/32-ai-coding-security-checklist.py) ·
> [TypeScript](../../examples/typescript/part-9/32-ai-coding-security-checklist.ts)

## Как использовать

Этот checklist применяется к AI-coding agent в IDE, terminal, cloud agent или CI/CD workflow.

Статусы:

| Status | Значение |
|---|---|
| Yes | реализовано, есть evidence |
| Partial | частично, нужен owner и срок |
| No | отсутствует |
| N/A | неприменимо, причина зафиксирована |

Правило:

```text
High-risk пункт со статусом No блокирует production usage.
```

## 1. Threat model

| ID | Проверка | Severity | Status |
|---|---|---|---|
| AC-TM-01 | AI-coding agent включён в threat model | High | TODO |
| AC-TM-02 | Есть DFD: repo → agent → shell/filesystem/git → CI/CD | High | TODO |
| AC-TM-03 | Repo считается источником untrusted context | High | TODO |
| AC-TM-04 | Shell/network/filesystem выделены как high-risk tools | High | TODO |
| AC-TM-05 | CI/CD и production path входят в scope | High | TODO |
| AC-TM-06 | MCP и skills входят в scope | High | TODO |
| AC-TM-07 | Определён blast radius coding agent | Medium | TODO |

## 2. Repository instructions

| ID | Проверка | Severity | Status |
|---|---|---|---|
| AC-RI-01 | `AGENTS.md` ревьюится | High | TODO |
| AC-RI-02 | `CLAUDE.md` / `GEMINI.md` ревьюятся, если используются | High | TODO |
| AC-RI-03 | `.github/copilot-instructions.md` ревьюится | High | TODO |
| AC-RI-04 | Path-specific instructions ревьюятся | Medium/High | TODO |
| AC-RI-05 | Issues/PR comments считаются untrusted | High | TODO |
| AC-RI-06 | README/docs не могут override security policy | High | TODO |
| AC-RI-07 | Instruction files не могут отключить approval/sandbox | High | TODO |
| AC-RI-08 | Изменение instruction files требует human review | High | TODO |
| AC-RI-09 | Setup instructions из README/docs не считаются trusted | High | TODO |

## 3. Permissions and sandbox

| ID | Проверка | Severity | Status |
|---|---|---|---|
| AC-PERM-01 | По умолчанию read-only или workspace-write | High | TODO |
| AC-PERM-02 | `danger-full-access` не используется по умолчанию | High | TODO |
| AC-PERM-03 | Network off by default | High | TODO |
| AC-PERM-04 | Shell требует approval | High | TODO |
| AC-PERM-05 | Workspace escape блокируется | High | TODO |
| AC-PERM-06 | `.env` и secrets не читаются агентом | High | TODO |
| AC-PERM-07 | Dependency install требует approval | High | TODO |
| AC-PERM-08 | CI/CD edits требуют mandatory review | Critical | TODO |
| AC-PERM-09 | Approval UI показывает command/path/url/risk | High | TODO |
| AC-PERM-10 | Approval timeout = deny | High | TODO |
| AC-PERM-11 | Network + shell одновременно только через отдельный approval | High | TODO |

## 4. Code review

| ID | Проверка | Severity | Status |
|---|---|---|---|
| AC-CR-01 | AI-generated code требует human review | High | TODO |
| AC-CR-02 | Агент не может merge напрямую | High | TODO |
| AC-CR-03 | Generated tests тоже ревьюятся | Medium | TODO |
| AC-CR-04 | Security-sensitive files требуют owner review | High | TODO |
| AC-CR-05 | Агент не может отключить failing security checks | High | TODO |
| AC-CR-06 | PR содержит trace/run_id задачи агента | Medium | TODO |
| AC-CR-07 | Diff risk classifier используется или заменён review policy | Medium | TODO |
| AC-CR-08 | Security Review Agent включён для agent-generated PR | High | TODO |
| AC-CR-09 | Security Review Agent не может сам merge/deploy | High | TODO |
| AC-CR-10 | Findings от Security Review Agent требуют human disposition | Medium | TODO |
| AC-CR-11 | Security Review Agent дополняет SAST/DAST, но не заменяет их | Medium | TODO |

## 5. Spec-driven workflow

| ID | Проверка | Severity | Status |
|---|---|---|---|
| AC-SPEC-01 | Перед задачей есть intent/spec | Medium | TODO |
| AC-SPEC-02 | Указан scope | Medium | TODO |
| AC-SPEC-03 | Указан out of scope | Medium | TODO |
| AC-SPEC-04 | Указаны forbidden changes | High | TODO |
| AC-SPEC-05 | Acceptance criteria определены | Medium | TODO |
| AC-SPEC-06 | Изменения вне scope блокируются или требуют review | High | TODO |

## 6. Supply chain

| ID | Проверка | Severity | Status |
|---|---|---|---|
| AC-SC-01 | Dependency changes считаются high-risk | High | TODO |
| AC-SC-02 | Lockfile changes ревьюятся | High | TODO |
| AC-SC-03 | Package scripts ревьюятся | High | TODO |
| AC-SC-04 | Dockerfile changes ревьюятся | High | TODO |
| AC-SC-05 | Versions pinned | Medium | TODO |
| AC-SC-06 | Есть dependency scanning | High | TODO |
| AC-SC-07 | Есть secret scanning | High | TODO |
| AC-SC-08 | Есть SBOM для production artifacts | Medium | TODO |
| AC-SC-09 | Агент не может отключить scanners | High | TODO |

## 7. CI/CD and production path

| ID | Проверка | Severity | Status |
|---|---|---|---|
| AC-CI-01 | Branch protection включён | High | TODO |
| AC-CI-02 | Required checks включены | High | TODO |
| AC-CI-03 | CODEOWNERS покрывает high-risk files | High | TODO |
| AC-CI-04 | CI token permissions минимальны | High | TODO |
| AC-CI-05 | Secrets недоступны untrusted PR | Critical | TODO |
| AC-CI-06 | Workflow changes требуют security review | Critical | TODO |
| AC-CI-07 | Deploy environment protected | High | TODO |
| AC-CI-08 | Agent-generated PR не auto-merged | High | TODO |
| AC-CI-09 | Artifact provenance сохраняется | Medium | TODO |

## 8. MCP

| ID | Проверка | Severity | Status |
|---|---|---|---|
| AC-MCP-01 | MCP servers в allowlist | High | TODO |
| AC-MCP-02 | MCP config changes требуют review | High | TODO |
| AC-MCP-03 | Tool metadata не считается policy | High | TODO |
| AC-MCP-04 | MCP tools проходят schema validation | High | TODO |
| AC-MCP-05 | Filesystem/shell MCP tools sandboxed | Critical | TODO |
| AC-MCP-06 | MCP egress ограничен | High | TODO |
| AC-MCP-07 | Есть kill-switch per MCP server | High | TODO |
| AC-MCP-08 | MCP calls логируются | Medium | TODO |
| AC-ADI-01 | Resource IDs / provenance из tool / issue / PR не trusted без deterministic validation ([§03](../part-2-input-security/03-prompt-injection-detection.md#agent-data-injection-adi)) | High | TODO |
| AC-ADI-02 | Agent не принимает self-asserted trust из tool response / structured metadata | High | TODO |

## 9. Skills / plugins

| ID | Проверка | Severity | Status |
|---|---|---|---|
| AC-SK-01 | Skills/plugins в allowlist | High | TODO |
| AC-SK-02 | Skills pinned by version/hash | High | TODO |
| AC-SK-03 | Skill description и body ревьюятся | High | TODO |
| AC-SK-04 | Optional scripts требуют sandbox | High | TODO |
| AC-SK-05 | Skills не могут override security policy | High | TODO |
| AC-SK-06 | Есть kill-switch per skill/plugin | Medium | TODO |
| AC-SK-07 | Skill updates требуют re-review | High | TODO |

## 10. Secrets and privacy

| ID | Проверка | Severity | Status |
|---|---|---|---|
| AC-SEC-01 | `.env` не читается агентом без явного разрешения | Critical | TODO |
| AC-SEC-02 | Secrets не попадают в model context | Critical | TODO |
| AC-SEC-03 | Secrets redacted в logs/traces | High | TODO |
| AC-SEC-04 | Shell output проверяется на secrets | High | TODO |
| AC-SEC-05 | Generated code не содержит hardcoded secrets | Critical | TODO |
| AC-SEC-06 | При exposure есть rotation procedure | High | TODO |

## 11. Testing and red teaming

| ID | Проверка | Severity | Status |
|---|---|---|---|
| AC-RT-01 | Есть malicious AGENTS.md test | High | TODO |
| AC-RT-02 | Есть malicious PR comment test | High | TODO |
| AC-RT-03 | Есть dependency poisoning test | High | TODO |
| AC-RT-04 | Есть CI workflow tampering test | High | TODO |
| AC-RT-05 | Есть MCP tool poisoning test | High | TODO |
| AC-RT-06 | Есть skill poisoning test | Medium/High | TODO |
| AC-RT-07 | Есть shell command abuse test | High | TODO |
| AC-RT-08 | High-risk regression blocks release | High | TODO |
| AC-RT-09 | Есть clean-repo / DNS-payload injection test (без рабочего shell) | High | TODO |

## 12. Incident response

| ID | Проверка | Severity | Status |
|---|---|---|---|
| AC-IR-01 | Есть playbook для compromised coding agent | High | TODO |
| AC-IR-02 | Есть playbook для secret exposure | Critical | TODO |
| AC-IR-03 | Есть playbook для malicious dependency | High | TODO |
| AC-IR-04 | Есть playbook для malicious MCP server | High | TODO |
| AC-IR-05 | Есть rollback branch/PR/deploy | High | TODO |
| AC-IR-06 | Есть clean-up git history procedure | Medium | TODO |
| AC-IR-07 | Есть audit retention | Medium | TODO |

## Production gate

```text
BLOCK production usage if:

- agent can run shell without approval;
- network is unrestricted;
- agent can read secrets;
- agent can change CI/CD without review;
- agent can merge/deploy directly;
- MCP servers are not allowlisted;
- skills/plugins are not reviewed;
- dependency changes are not reviewed;
- generated code does not require human review;
- no kill-switch;
- no incident owner.
```

## Go snippet: checklist validator

```go
package aichecklist

import "errors"

type Severity string
type Status string

const (
	Critical Severity = "Critical"
	High     Severity = "High"
	Medium   Severity = "Medium"
	Low      Severity = "Low"

	Yes     Status = "Yes"
	Partial Status = "Partial"
	No      Status = "No"
	NA      Status = "N/A"
)

type Item struct {
	ID       string
	Title    string
	Severity Severity
	Status   Status
	Owner    string
	Evidence []string
	Reason   string
}

func Validate(items []Item) error {
	for _, item := range items {
		if item.ID == "" || item.Title == "" {
			return errors.New("empty required fields")
		}

		if (item.Severity == Critical || item.Severity == High) && item.Status == No {
			return errors.New("blocking checklist item: " + item.ID)
		}

		if item.Status == Partial && item.Owner == "" {
			return errors.New("partial item requires owner: " + item.ID)
		}

		if item.Status == Yes && (item.Severity == Critical || item.Severity == High) && len(item.Evidence) == 0 {
			return errors.New("high/critical item requires evidence: " + item.ID)
		}

		if item.Status == NA && item.Reason == "" {
			return errors.New("N/A requires reason: " + item.ID)
		}
	}

	return nil
}
```

## Definition of Done

AI-coding agent можно считать минимально безопасным для controlled usage, если:

- repo instructions reviewed;
- shell/network controlled;
- workspace isolated;
- dependency/CI/CD changes reviewed;
- generated code reviewed by human;
- agent cannot merge/deploy directly;
- MCP servers allowlisted;
- skills pinned and reviewed;
- secrets isolated from model context;
- audit/traces enabled;
- kill-switch exists;
- red team tests cover repo poisoning and tool abuse;
- incident response owner назначен.

## Литература

- [Список литературы](../literature.md#стандарты-и-фреймворки)
- [OpenAI Codex — Agent approvals and security](https://developers.openai.com/codex/agent-approvals-security)
- [OpenAI Codex — Sandboxing](https://developers.openai.com/codex/concepts/sandboxing)
- [GitHub Copilot cloud agent](https://docs.github.com/en/copilot/concepts/agents/cloud-agent/about-cloud-agent)
- [AGENTS.md](https://agents.md/)
- [GitHub Copilot — custom instructions](https://docs.github.com/copilot/customizing-copilot/adding-custom-instructions-for-github-copilot)
- [OpenAI Codex — Skills](https://developers.openai.com/codex/skills)
- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)
- [Model Context Protocol — Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)

## См. также

- [03 — Prompt Injection Detection (ADI)](../part-2-input-security/03-prompt-injection-detection.md#agent-data-injection-adi)
- [25 — Security-by-Design чек-лист](../part-8-practice/25-security-by-design-checklist.md)
- [26 — AI-coding agent: модель угроз](26-ai-coding-agent-threat-model.md)
- [30 — AI Coding Supply Chain](30-ai-coding-supply-chain.md)
- [31 — CI/CD, MCP, Skills и production path](31-ci-cd-mcp-skills-production-path.md)
