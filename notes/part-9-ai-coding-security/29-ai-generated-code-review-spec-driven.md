---
tags: [ai-security, ai-coding, code-review, spec-driven, pull-request]
часть: "Часть IX — AI Coding Agent Security"
статус: готово
обновлено: 2026-06-09
изменения: "Добавлены code review, spec-driven workflow и diff risk classifier; дополнен Security Review Agent (сравнение с SAST, security boundary)."
---

# 29 — AI-generated code review и spec-driven workflow

> Навигация: [Оглавление](../../README.md) · [← Назад](28-coding-agent-permissions-sandbox-approval.md) · [Вперёд →](30-ai-coding-supply-chain.md)

*Кратко: AI-generated code нельзя автоматически принимать. Безопасный workflow: spec → plan → tasks → diff → tests → human review → PR → merge gate.*

## Суть

AI-coding agent генерирует не просто текст.

Он генерирует:

- код;
- тесты;
- конфиги;
- миграции;
- зависимости;
- workflow;
- Dockerfile;
- shell scripts;
- docs;
- prompts/instructions.

Review должен проверять не только “работает ли”, но и:

```text
не ослабил ли агент безопасность?
не добавил ли supply chain risk?
не удалил ли проверку?
не спрятал ли изменение в тестах или конфиге?
```

Главное правило:

> AI-generated code должен проходить human review до merge/deploy.

## Spec-driven как security control

Spec-driven workflow снижает риск “vibe coding”:

```text
1. Intent
2. Scope
3. Constraints
4. Forbidden changes
5. Acceptance criteria
6. Plan
7. Tasks
8. Implementation
9. Tests
10. Review
```

Без spec агент может “помочь” слишком широко:

```text
почини тесты → удалил тест
ускорь сборку → отключил security scan
исправь ошибку auth → разрешил anonymous access
```

## DFD

```mermaid
flowchart LR
    Developer[External Entity: Developer]

    subgraph Spec["Trust Boundary: Specification"]
        Intent[Data Store: Intent]
        Constraints[Data Store: Constraints]
        Tasks[Data Store: Tasks]
        Acceptance[Data Store: Acceptance Criteria]
    end

    subgraph Runtime["Trust Boundary: Coding Agent"]
        Planner[Process: Plan Generator]
        Implementer[Process: Code Generator]
        TestRunner[Process: Test Runner]
        DiffAnalyzer[Process: Diff Risk Analyzer]
    end

    subgraph Repo["Trust Boundary: Repository"]
        Code[(Data Store: Code)]
        Tests[(Data Store: Tests)]
        Configs[(Data Store: Configs)]
        Workflows[(Data Store: Workflows)]
        Dependencies[(Data Store: Dependencies)]
    end

    subgraph Review["Trust Boundary: Review and Merge"]
        PR[Data Store: Pull Request]
        HumanReview[Process: Human Review]
        CIGate[Process: CI / Security Gates]
        Merge[Process: Merge]
    end

    Developer --> Intent
    Intent --> Constraints
    Constraints --> Tasks
    Tasks --> Acceptance
    Acceptance --> Planner
    Planner --> Implementer
    Code --> Implementer
    Tests --> TestRunner
    Implementer --> Code
    Implementer --> Tests
    Implementer --> Configs
    Implementer --> Workflows
    Implementer --> Dependencies
    Implementer --> DiffAnalyzer
    DiffAnalyzer --> PR
    PR --> HumanReview
    PR --> CIGate
    HumanReview --> Merge
    CIGate --> Merge
```

## Review checklist по diff

| Изменение | Risk | Что смотреть |
|---|---|---|
| Source code | Medium | логика, auth, validation, error handling |
| Tests | Medium | не удалены ли важные проверки |
| Dependencies | High | новая зависимость, scripts, lockfile |
| CI/CD | Critical | permissions, secrets, deploy, scans |
| Dockerfile | High | base image, curl scripts, secrets |
| Configs | High | auth disabled, debug enabled |
| Prompts/instructions | High | security override, hidden instructions |
| MCP config | High | новый server/tool |
| Scripts | High | shell injection, network, destructive commands |

## Типовые AI-code review риски

| Риск | Пример | Severity |
|---|---|---|
| Security check removed | агент удалил failing test/security scan | High |
| Fake fix | агент изменил тест, а не код | Medium |
| Overbroad permissions | workflow получил `permissions: write-all` | Critical |
| Unsafe dependency | новая зависимость с postinstall script | High |
| Secret in code | агент вставил token в config | Critical |
| Input validation removed | агент упростил handler | High |
| Auth bypass | агент исправил ошибку через отключение проверки прав | Critical |
| Logging sensitive data | агент добавил debug log с PII/secrets | High |
| Prompt injection in docs | агент добавил вредные instructions в docs | High |

## Go snippet: diff risk classifier

```go
package codereview

import (
	"path/filepath"
	"strings"
)

type Risk string

const (
	Low      Risk = "Low"
	Medium   Risk = "Medium"
	High     Risk = "High"
	Critical Risk = "Critical"
)

type ChangedFile struct {
	Path      string
	Additions int
	Deletions int
}

func ClassifyFile(path string) Risk {
	p := filepath.ToSlash(filepath.Clean(path))

	switch {
	case strings.HasPrefix(p, ".github/workflows/"):
		return Critical
	case p == "Dockerfile" || strings.HasSuffix(p, ".Dockerfile"):
		return High
	case p == "package.json" || p == "package-lock.json" || p == "go.mod" || p == "go.sum":
		return High
	case p == "AGENTS.md" || p == "CLAUDE.md" || strings.HasPrefix(p, ".github/instructions/"):
		return High
	case strings.Contains(p, "auth") || strings.Contains(p, "permission") || strings.Contains(p, "policy"):
		return High
	case strings.HasSuffix(p, "_test.go") || strings.Contains(p, "/test"):
		return Medium
	default:
		return Medium
	}
}
```

## Go snippet: PR gate

```go
type PullRequest struct {
	ID                 string
	Author             string
	Files              []ChangedFile
	AgentGenerated     bool
	ApprovedByHuman    bool
	SecurityApproved   bool
	CIPassed           bool
	SecurityScanPassed bool
}

func RequiresSecurityReview(pr PullRequest) bool {
	if pr.AgentGenerated {
		return true
	}

	for _, f := range pr.Files {
		risk := ClassifyFile(f.Path)
		if risk == High || risk == Critical {
			return true
		}
	}

	return false
}

func CanMerge(pr PullRequest) bool {
	if !pr.ApprovedByHuman {
		return false
	}
	if !pr.CIPassed || !pr.SecurityScanPassed {
		return false
	}
	if RequiresSecurityReview(pr) && !pr.SecurityApproved {
		return false
	}
	return true
}
```

## Spec template

```md
# Spec

## Intent
Что надо изменить.

## Scope
Какие файлы/модули можно менять.

## Out of scope
Что менять нельзя.

## Security constraints
- не менять auth без отдельного review;
- не менять CI/CD;
- не добавлять dependencies без approval;
- не читать `.env`;
- не отключать тесты.

## Acceptance criteria
- тесты проходят;
- security checks проходят;
- diff ограничен scope;
- нет новых high-risk dependencies.
```

## Anti-patterns

```text
“Просто почини как-нибудь”
“Сделай чтобы тесты проходили”
“Игнорируй warnings”
“Поставь любую библиотеку”
“Можешь менять что хочешь”
“Если мешают проверки — убери”
```

## Security Review Agent

Security Review Agent — это специализированный AI-reviewer, который проверяет agent-generated diff / PR на security regressions.

Он должен проверять:

- auth / authorization regressions;
- input validation;
- secrets / PII leakage;
- insecure dependencies;
- CI/CD workflow changes;
- dangerous tool auto-approvals;
- prompt injection surfaces;
- MCP / skill / plugin changes;
- unsafe shell/network usage.

Security Review Agent не должен иметь право сам merge/deploy.
Его результат — finding/comment, а решение остаётся за человеком и CI gates.

### Отличие от SAST/DAST

| Свойство | SAST/DAST | Security Review Agent |
|---|---|---|
| Проверка по правилам | да | частично |
| Понимание PR/diff/контекста | ограниченно | лучше |
| Объяснение проблемы и remediation | ограниченно | да |
| Учёт agent-specific рисков (tool auto-approval, MCP, prompt injection) | обычно нет | да |
| Может пропустить проблему | да | да |

Security Review Agent — это дополнительный reviewer, а не security boundary. Он не заменяет human review, SAST, dependency/secret scanning, branch protection, required checks, sandbox, approval и least privilege.

## Чек-лист

- [ ] Перед coding task есть intent/spec.
- [ ] Указан scope.
- [ ] Указан out of scope.
- [ ] Указаны forbidden changes.
- [ ] Dependency changes требуют approval.
- [ ] CI/CD changes требуют approval.
- [ ] Generated code проходит human review.
- [ ] Generated tests тоже проходят review.
- [ ] Агент не может сам merge.
- [ ] PR содержит trace/run_id agent task.
- [ ] CI/security gates обязательны.
- [ ] Security-sensitive diff требует owner review.

## Литература

- [Список литературы](../literature.md#практические-руководства)
- [Cursor — Security Review](https://cursor.com/docs/security-review)
- [GitHub Copilot cloud agent](https://docs.github.com/en/copilot/concepts/agents/cloud-agent/about-cloud-agent)
- [GitHub Spec Kit](https://github.com/github/spec-kit)
- [GitHub — Spec-driven development with Spec Kit](https://developer.microsoft.com/blog/spec-driven-development-spec-kit)
- [GitHub agentic security principles](https://github.blog/ai-and-ml/github-copilot/how-githubs-agentic-security-principles-make-our-ai-agents-as-secure-as-possible/)
- [OpenAI Codex — Agent approvals and security](https://developers.openai.com/codex/agent-approvals-security)

## См. также

- [14 — Human-in-the-Loop](../part-5-control-observability/14-human-in-the-loop.md)
- [20 — Red Teaming и Adversarial Testing](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md)
- [22 — Supply Chain Security](../part-7-testing-compliance/22-supply-chain-security.md)
