---
tags: [ai-security, ai-coding, cicd, mcp, skills, production]
часть: "Часть IX — AI Coding Agent Security"
статус: готово
обновлено: 2026-06-09
изменения: "Добавлен раздел о CI/CD, MCP, skills и production path для coding agents."
---

# 31 — CI/CD, MCP, Skills и production path

> Навигация: [Оглавление](../../README.md) · [← Назад](30-ai-coding-supply-chain.md) · [Вперёд →](32-ai-coding-security-checklist.md)

*Кратко: AI-coding agent опасен не только локальными изменениями. Через CI/CD, MCP и skills он может повлиять на путь к production.*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-9/31-ci-cd-mcp-skills-production-path.py) ·
> [TypeScript](../../examples/typescript/part-9/31-ci-cd-mcp-skills-production-path.ts)

## Суть

AI-coding agent часто работает не один:

```text
IDE / terminal agent → repo changes → branch → PR → CI/CD → artifact → deploy
```

Параллельно он может использовать:

- MCP-серверы;
- skills/plugins;
- package registries;
- browser tools;
- database tools;
- shell tools;
- cloud environments.

Главный риск:

> агент может изменить не только код, но и инфраструктуру, через которую код попадает в production.

## DFD

```mermaid
flowchart LR
    Developer[External Entity: Developer]

    subgraph Coding["Trust Boundary: Coding Agent"]
        Agent[Process: Coding Agent]
        Policy[Process: Tool / Permission Policy]
        MCPClient[Process: MCP Client]
        SkillLoader[Process: Skill Loader]
    end

    subgraph Repo["Trust Boundary: Repository"]
        Branch[(Data Store: Branch)]
        PR[(Data Store: Pull Request)]
        Workflows[(Data Store: CI/CD Workflows)]
        MCPConfig[(Data Store: MCP Config)]
        SkillFiles[(Data Store: Skills)]
    end

    subgraph ExternalTools["Trust Boundary: External Tools"]
        MCPServer[External System: MCP Server]
        PackageRegistry[External System: Package Registry]
        Cloud[External System: Cloud / Deploy Environment]
    end

    subgraph CICD["Trust Boundary: CI/CD"]
        Runner[Process: CI Runner]
        Secrets[(Data Store: CI Secrets)]
        Artifact[(Data Store: Build Artifact)]
        Deploy[Process: Deploy]
        Environments[(Data Store: Protected Environments)]
    end

    subgraph Review["Trust Boundary: Governance"]
        HumanReview[Process: Human Review]
        RequiredChecks[Process: Required Checks]
        BranchProtection[Process: Branch Protection]
        Audit[(Data Store: Audit Logs)]
    end

    Developer --> Agent
    Agent --> Policy
    Policy --> MCPClient
    Policy --> SkillLoader
    MCPClient --> MCPServer
    SkillLoader --> SkillFiles
    Agent --> Branch
    Branch --> PR
    PR --> HumanReview
    PR --> RequiredChecks
    PR --> Runner
    Workflows --> Runner
    Runner --> Secrets
    Runner --> Artifact
    Artifact --> Deploy
    Deploy --> Cloud
    Environments --> Deploy
    BranchProtection --> PR
    HumanReview --> PR
    RequiredChecks --> PR
    Agent --> MCPConfig
    MCPConfig --> MCPClient
    Policy --> Audit
    MCPClient --> Audit
    Runner --> Audit
```

## CI/CD threat model

| Угроза | Пример | Risk |
|---|---|---|
| Workflow injection | агент добавляет шаг, который печатает secrets | Critical |
| Overbroad token permissions | `permissions: write-all` | Critical |
| Disable scanner | агент отключает SAST/dependency scan | High |
| Bypass required checks | агент меняет workflow name/condition | High |
| Artifact poisoning | build artifact содержит вредный код | Critical |
| PR from fork + secrets | workflow ошибочно отдаёт secrets fork PR | Critical |
| Deploy gate bypass | агент меняет environment protection | Critical |
| Auto-merge by agent | агент сам мержит PR | High |

## MCP threat model в AI-coding

| Угроза | Пример | Risk |
|---|---|---|
| MCP tool poisoning | tool description содержит скрытые инструкции | High |
| Shadow server | новый MCP server появляется без review | High |
| Context injection | MCP resource влияет на coding plan | High |
| Filesystem overreach | MCP server читает весь home directory | Critical |
| Shell tool abuse | MCP tool запускает команды | Critical |
| Egress bypass | MCP server отправляет данные наружу | Critical |
| Cross-server contamination | output одного server влияет на другой tool | High |

## Skills threat model

| Угроза | Пример | Risk |
|---|---|---|
| Skill poisoning | description безопасный, body вредный | High |
| Rug pull | skill обновился и получил вредный script | High |
| Over-permissioned skill | skill запускает shell/network без необходимости | High |
| Hidden workflow | skill меняет CI/dependencies | High |
| Instruction override | skill просит игнорировать security policy | High |
| Unreviewed sharing | skill принесён из внешнего источника | Medium/High |

## Production path controls

| Контроль | Для чего |
|---|---|
| Branch protection | агент не может напрямую писать в protected branch |
| Required reviews | human review до merge |
| CODEOWNERS | security-sensitive files требуют owner review |
| Required checks | тесты, scan, lint, policy gates |
| Protected environments | deploy требует approval |
| Least privilege token | CI токены без лишних прав |
| No secrets for untrusted PR | защита fork PR |
| Artifact signing | контроль происхождения artifact |
| SBOM | visibility dependencies |
| Audit logs | расследование действий агента |

## Go snippet: high-risk path detector

```go
package productionpath

import (
	"path/filepath"
	"strings"
)

func IsProductionPath(path string) bool {
	p := filepath.ToSlash(filepath.Clean(path))

	if strings.HasPrefix(p, ".github/workflows/") {
		return true
	}
	if strings.HasPrefix(p, "deploy/") || strings.HasPrefix(p, "k8s/") || strings.HasPrefix(p, "helm/") {
		return true
	}
	if p == "Dockerfile" || strings.HasSuffix(p, ".Dockerfile") {
		return true
	}
	if strings.Contains(p, "terraform") || strings.HasSuffix(p, ".tf") {
		return true
	}
	if p == "CODEOWNERS" || strings.HasSuffix(p, "/CODEOWNERS") {
		return true
	}
	return false
}
```

## Go snippet: production gate

```go
type PR struct {
	ID               string
	AgentGenerated   bool
	ChangedFiles     []string
	HumanApproved    bool
	SecurityApproved bool
	RequiredChecksOK bool
}

func NeedsProductionReview(pr PR) bool {
	if pr.AgentGenerated {
		return true
	}
	for _, path := range pr.ChangedFiles {
		if IsProductionPath(path) {
			return true
		}
	}
	return false
}

func CanEnterProductionPath(pr PR) bool {
	if !pr.RequiredChecksOK {
		return false
	}
	if NeedsProductionReview(pr) && !pr.HumanApproved {
		return false
	}
	if NeedsProductionReview(pr) && !pr.SecurityApproved {
		return false
	}
	return true
}
```

## MCP/Skills controls

| Контроль | MCP | Skills |
|---|---:|---:|
| allowlist | да | да |
| owner | да | да |
| version pinning | да | да |
| permission review | да | да |
| schema validation | да | частично |
| sandbox | для command tools | для scripts |
| egress control | обязательно | если есть network |
| audit | обязательно | обязательно |
| kill-switch | per server | per skill |
| update review | обязательно | обязательно |

## Чек-лист

- [ ] Agent-generated PR не может merge без человека.
- [ ] Branch protection включён.
- [ ] Required checks включены.
- [ ] CODEOWNERS покрывает CI/CD, security, deploy files.
- [ ] CI token permissions минимальны.
- [ ] Secrets не доступны untrusted PR.
- [ ] Workflow changes требуют security review.
- [ ] Deploy environments protected.
- [ ] MCP servers в allowlist.
- [ ] MCP config changes требуют review.
- [ ] Skills/plugins pinned.
- [ ] Skills/scripts проходят review.
- [ ] Есть kill-switch per MCP server / skill.
- [ ] Agent-generated artifacts имеют provenance.
- [ ] Есть audit по PR, CI, deploy.

## Литература

- [Список литературы](../literature.md#mcp)
- [GitHub Copilot cloud agent](https://docs.github.com/en/copilot/concepts/agents/cloud-agent/about-cloud-agent)
- [GitHub Actions — Security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [Model Context Protocol — Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [OpenAI Codex — Skills](https://developers.openai.com/codex/skills)
- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)
- [OWASP Practical Guide for Secure MCP Server Development](https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/)

## См. также

- [19 — MCP Security](../part-6-multi-agent-security/19-mcp-security.md)
- [22 — Supply Chain Security](../part-7-testing-compliance/22-supply-chain-security.md)
- [23 — Incident Response и Recovery](../part-7-testing-compliance/23-incident-response-recovery.md)
- [30 — AI Coding Supply Chain](30-ai-coding-supply-chain.md)
