---
tags: [ai-security, agents, supply-chain, sbom, dependencies, models, mcp]
часть: "Часть VII — Тестирование и compliance"
статус: готово
обновлено: 2026-08-04
изменения: "Model provenance / backdoors в весах; pin digest; дистилляция и semantic triggers; lit ×6 arXiv."
---

# 22 — Supply Chain Security

> Навигация: [Оглавление](../../README.md) · [← Назад](21-compliance-standards.md) · [Вперёд →](23-incident-response-recovery.md)

*Кратко: supply chain security для AI-агента — это контроль всего, что попадает в runtime: код, зависимости, модели, prompts, datasets, tools, MCP servers, containers, CI/CD и конфигурации.*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-7/22-supply-chain-security.py) ·
> [TypeScript](../../examples/typescript/part-7/22-supply-chain-security.ts)

## Суть

В классическом backend supply chain — это зависимости, контейнеры, CI/CD и deployment.

В AI-агенте supply chain шире:

- Go/Python/JS зависимости;
- Docker images;
- prompts;
- model providers;
- model versions;
- eval datasets;
- vector indexes;
- MCP servers;
- tools;
- browser automation;
- shell scripts;
- plugins;
- guardrails;
- policy files;
- CI/CD workflows;
- secrets and configs.

Главная мысль:

> Агентная supply chain опасна тем, что новый tool или MCP server может дать агенту новые capabilities без изменения основного кода.

## DFD

```mermaid
flowchart LR
    subgraph Sources["Trust Boundary: External Sources"]
        Repos[External System: Git Repositories]
        Packages[External System: Package Registries]
        Models[External System: Model Providers]
        MCPServers[External System: MCP Servers]
        Containers[External System: Container Registries]
        Datasets[External System: Datasets / Eval Sets]
    end

    subgraph Build["Trust Boundary: Build and CI"]
        CI[Process: CI Pipeline]
        Scanners[Process: Scanners]
        SBOM[Data Store: SBOM]
        Attestations[Data Store: Build Attestations]
        Artifacts[Data Store: Build Artifacts]
    end

    subgraph Runtime["Trust Boundary: Agent Runtime"]
        Agent[Process: Agent]
        ToolRegistry[Data Store: Tool Registry]
        PromptStore[Data Store: Prompt / Policy Store]
        ModelConfig[Data Store: Model Config]
        Deps[Data Store: Dependencies]
    end

    subgraph Monitoring["Trust Boundary: Runtime Monitoring"]
        Audit[(Data Store: Audit Logs)]
        Alerts[Process: Alerts]
    end

    Repos --> CI
    Packages --> CI
    Containers --> CI
    Datasets --> CI
    Models --> ModelConfig
    MCPServers --> ToolRegistry

    CI --> Scanners
    Scanners --> SBOM
    Scanners --> Attestations
    CI --> Artifacts

    Artifacts --> Agent
    SBOM --> Deps
    ToolRegistry --> Agent
    PromptStore --> Agent
    ModelConfig --> Agent

    Agent --> Audit
    Audit --> Alerts
```

## Что входит в AI supply chain

| Компонент | Риски |
|---|---|
| Dependencies | malicious package, dependency confusion, vulnerable transitive deps |
| Container images | устаревшие base images, embedded secrets |
| Prompts | prompt injection в system/developer prompts, несанкционированное изменение |
| Policies | ослабление RBAC, egress, approval, rate limits |
| Models | смена поведения модели, неподтверждённая версия, provider risk |
| Datasets | poisoning, leakage, copyrighted/sensitive data |
| Vector DB / index | poisoned embeddings, cross-tenant leakage |
| Tools | dangerous side effects, hidden network calls |
| MCP servers | command execution, excessive permissions, malicious metadata |
| CI/CD | token leakage, compromised workflow, unreviewed deploy |
| Secrets | hardcoded keys, overbroad tokens, missing rotation |

### Instruction и skill supply chain

В AI-coding и IDE-агентах появляется отдельный управляющий слой — не код приложения, а инструкции и skills, которые задают поведение агента:

- `AGENTS.md`, `.cursor/rules`, `CLAUDE.md`, steering files — это **не документация**, а недоверенный контент с правами на поведение агента; версионируется и ревьюится как код.
- **Agent Skills**: видимое `description` (что видит человек при выборе) vs скрытое `body` (progressive disclosure — агент видит больше при активации).
- **Skill poisoning**: безопасное `description` + вредный `body` или optional script.
- **Rug pull**: benign skill/MCP server/модель меняет поведение после consent или обновления на `latest` — pin по version или hash, не `latest`.

Подробный разбор AI-coding supply chain — в [30 — AI Coding Supply Chain](../part-9-ai-coding-security/30-ai-coding-supply-chain.md).

## Угроза / контекст

| Угроза | Пример | Risk |
|---|---|---|
| Malicious dependency | пакет добавляет network exfiltration | High |
| Dependency confusion | устанавливается пакет из public registry вместо internal | High |
| Prompt tampering | system prompt изменён без review | High |
| Tool poisoning | новый tool описан как read-only, но выполняет write | High |
| MCP server compromise | MCP server получает доступ к файлам и shell | Critical |
| Model version drift | новая модель меняет tool-use поведение | Medium |
| Untrusted model provenance | дообученная или аблитерированная модель неизвестного происхождения; поведение и safety-гарантии не подтверждены | High |
| Model weight backdoor / trigger | закладка в весах: срабатывает на semantic trigger или переживает distillation teacher→student; «clean» safety fine-tune не доказывает отсутствие триггера | High |
| Dataset poisoning | eval set или knowledge base содержит вредные инструкции | High |
| Secret leakage in build | token попал в logs или container layer | High |
| Unpinned image | build подтянул новый base image без проверки | Medium |
| No provenance | неизвестно, откуда взялся artifact | Medium |

## Подходы и контрмеры

### 1. Pin versions

Фиксировать:

- dependency versions;
- model versions;
- Docker image digests;
- MCP server versions;
- prompt versions;
- policy versions;
- tool schema versions.

### 2. SBOM

Хранить Software Bill of Materials:

```text
artifact → dependencies → versions → hashes → licenses → vulnerabilities
```

Для агентной системы дополнительно:

```text
agent SBOM → tools → prompts → model config → MCP servers → policies
```

### 3. Review для capabilities

Любой новый tool/MCP server — это изменение capability surface.

Нужен review:

```text
new tool → threat model update → policy update → tests → approval → deploy
```

### 4. Prompt/policy as code

Prompts и security policies должны жить как код:

- version control;
- code review;
- diff;
- tests;
- owners;
- rollback;
- release notes.

### 5. CI gates

Примеры gates:

- dependency scan;
- secret scan;
- container scan;
- license check;
- prompt diff review;
- tool schema validation;
- MCP server allowlist check;
- red team regression suite;
- SBOM generation.

### 6. Runtime verification

CI недостаточно.

В runtime проверять:

- разрешён ли tool;
- совпадает ли tool schema hash;
- разрешён ли MCP server;
- не изменилась ли model version;
- не отключены ли guardrails;
- не изменились ли policy rules.

### 7. Evaluation partner / внешняя лаборатория

Сторонняя платформа оценки — часть **agent supply chain**, не «чужой процесс вне периметра». Если cyber/eval-прогон идёт через внешнюю лабораторию, недостаточно, что «своя» infra настроена правильно: misconfiguration на стыке заказчик↔partner даёт тот же класс рисков, что слабый sandbox или размытый scope.

> **Правило:** внешняя лаборатория проходит **тот же** контроль среды (containment, secrets, kill-switch, signed scope), что внутренняя red-team / eval команда. Partner **не** расширяет scope сам — цели только из подписанного manifest ([§08](../part-3-processing-security/08-sandboxing.md#sandbox--isolation-containment-escape), [`EVAL-TARGET-BOUNDARY-01`](20-red-teaming-adversarial-testing.md#target-boundary-evals-eval-target-boundary-01)).

Публичный кейс (июль 2026): инцидент при оценке с участием внешней лаборатории показал, что ошибка конфигурации партнёра / стыка может затронуть внешние системы, даже если внутренняя команда считала стенд изолированным. Факты — в тексте без вторичных URL; границы evaluation — [arXiv 2607.25379](https://arxiv.org/abs/2607.25379).

#### Checklist внешней лаборатории

- [ ] Описана фактическая сетевая архитектура.
- [ ] Изоляция подтверждена **тестом**, а не заявлением.
- [ ] Нет общих production-секретов с партнёром.
- [ ] Есть **независимый** kill switch у заказчика (не только у partner).
- [ ] Заказчик получает телеметрию в реальном времени.
- [ ] Описана процедура уведомления третьих сторон при ошибочном воздействии.
- [ ] Партнёр не может самостоятельно расширить scope.
- [ ] Образ среды зафиксирован по digest.
- [ ] Изменения инфраструктуры требуют повторной проверки checklist.
- [ ] Определено, кто отвечает за ошибочное воздействие на внешнюю систему.

Якорь в security evals: [EV-11](20-red-teaming-adversarial-testing.md) · RoE: [AI Agent Security Testing Guide](../../guides/ai-agent-security-testing-guide.md). TTAC / `evaluation_partner` в отчёте — [§23 Autonomous-agent IR](23-incident-response-recovery.md#playbook-autonomous-agent-ir-containment) · [incident-report §6.1](../../templates/incident-report-template.md).

<a id="model-provenance-backdoors"></a>

### 8. Model provenance / backdoors в весах

Веса модели — такой же artifact supply chain, как образ контейнера или MCP server. Нужны: источник весов, кто дообучал / дистиллировал, pin по **digest** (не только tag / `latest`). Tag «официальный» без digest не фиксирует содержимое.

> **Правило:** нельзя доказать отсутствие триггера в весах. Доверие к safety fine-tune или «маленькой» student-модели — не контроль. Компенсация — **внешние** границы runtime: sandbox, egress allowlist, tool allowlist, HITL ([§08](../part-3-processing-security/08-sandboxing.md), [§13](../part-4-output-security/13-egress-control-data-exfiltration.md), [§14](../part-5-control-observability/14-human-in-the-loop.md)).

Операционные факты из исследований (первоисточники — [literature](../literature.md#академические-исследования)):

- **Дистилляция teacher→student:** закладка в крупной модели может перейти в мелкую при обучении; student не «чище» только потому, что меньше ([arXiv 2509.23871](https://arxiv.org/abs/2509.23871)).
- **RLHF / semantic triggers:** триггер по смыслу (например эмоциональный или насильственный контент), не по фиксированным токенам — токен-фильтр недостаточен ([arXiv 2510.09260](https://arxiv.org/abs/2510.09260)).
- **Сложные mapping / скрытые триггеры:** сценарии вроде All-to-X устойчивее простых «один триггер → один класс»; методики извлечения триггеров существуют, но это **не** гарантия «модель без backdoor» ([arXiv 2511.13356](https://arxiv.org/abs/2511.13356), [arXiv 2602.03085](https://arxiv.org/abs/2602.03085)).

#### Checklist model provenance

- [ ] Веса / artifact модели pinned by **digest** (не только version tag).
- [ ] Provenance задокументирован: источник, кто fine-tune / distill, цепочка teacher→student если есть.
- [ ] Произвольные аблитерированные / «расцензуренные» веса без security review — запрет.
- [ ] Runtime controls (sandbox, egress, tool allowlist, HITL) обязательны — отсутствие гарантии clean weights принято явно.

## Пример (Go)

### Описание AI artifact inventory

```go
package supplychain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

type ArtifactType string

const (
	Dependency ArtifactType = "dependency"
	Container  ArtifactType = "container"
	Prompt     ArtifactType = "prompt"
	Policy     ArtifactType = "policy"
	Tool       ArtifactType = "tool"
	MCPServer  ArtifactType = "mcp_server"
	Model      ArtifactType = "model"
	Dataset    ArtifactType = "dataset"
)

type Artifact struct {
	Name        string       `json:"name"`
	Type        ArtifactType `json:"type"`
	Version     string       `json:"version"`
	Hash        string       `json:"hash"`
	Source      string       `json:"source"`
	Owner       string       `json:"owner"`
	Reviewed    bool         `json:"reviewed"`
	Capabilities []string    `json:"capabilities,omitempty"`
}
```

### Inventory validation

```go
func ValidateInventory(items []Artifact) error {
	for _, item := range items {
		if item.Name == "" || item.Type == "" || item.Version == "" {
			return errors.New("artifact has required empty fields")
		}

		if item.Owner == "" {
			return errors.New("artifact has no owner: " + item.Name)
		}

		if item.Hash == "" && item.Type != Model {
			return errors.New("artifact has no hash: " + item.Name)
		}

		if isCapabilityArtifact(item.Type) && !item.Reviewed {
			return errors.New("capability artifact is not reviewed: " + item.Name)
		}
	}

	return nil
}

func isCapabilityArtifact(t ArtifactType) bool {
	return t == Tool || t == MCPServer || t == Policy || t == Prompt
}
```

### Hash prompt / policy

```go
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func NewPromptArtifact(name string, version string, source string, owner string, content []byte) Artifact {
	return Artifact{
		Name:     name,
		Type:     Prompt,
		Version:  version,
		Hash:     HashBytes(content),
		Source:   source,
		Owner:    owner,
		Reviewed: true,
	}
}
```

### Tool schema hash check

```go
type ToolSchema struct {
	Name    string         `json:"name"`
	Version string         `json:"version"`
	Schema  map[string]any `json:"schema"`
	Hash    string         `json:"hash"`
}

func ComputeSchemaHash(schema map[string]any) (string, error) {
	b, err := json.Marshal(schema)
	if err != nil {
		return "", err
	}
	return HashBytes(b), nil
}

func ValidateToolSchema(schema ToolSchema) error {
	actual, err := ComputeSchemaHash(schema.Schema)
	if err != nil {
		return err
	}
	if actual != schema.Hash {
		return errors.New("tool schema hash mismatch: " + schema.Name)
	}
	return nil
}
```

### Allowlist для runtime artifacts

```go
type Allowlist struct {
	Allowed map[string]string // name -> hash
}

func (a Allowlist) Check(item Artifact) error {
	expectedHash, ok := a.Allowed[item.Name]
	if !ok {
		return errors.New("artifact not allowlisted: " + item.Name)
	}

	if expectedHash != item.Hash {
		return errors.New("artifact hash mismatch: " + item.Name)
	}

	return nil
}
```

## Supply chain checklist

- [ ] Dependencies pinned.
- [ ] Container images pinned by digest.
- [ ] Есть SBOM.
- [ ] Есть secret scanning.
- [ ] Есть dependency scanning.
- [ ] Есть container scanning.
- [ ] Prompts хранятся в version control.
- [ ] Security policies хранятся в version control.
- [ ] Tool schemas версионируются.
- [ ] MCP servers в allowlist.
- [ ] Новый tool требует threat model update.
- [ ] Новый MCP server требует review.
- [ ] Model version фиксируется; веса pinned by digest (см. [Model provenance / backdoors](#model-provenance-backdoors)).
- [ ] Model provenance проверен: источник весов, кто дообучал / дистиллировал; не используются произвольные аблитерированные или «расцензуренные» модели без review.
- [ ] Нет опоры на «модель без backdoor» как на единственный контроль — sandbox / egress / tool allowlist / HITL включены.
- [ ] Eval datasets версионируются.
- [ ] Vector index имеет source/provenance.
- [ ] CI запускает red team regression tests.
- [ ] Runtime проверяет hashes/versions для critical artifacts.
- [ ] Есть rollback.
- [ ] Instruction files (`AGENTS.md`, `.cursor/rules`, `CLAUDE.md`) версионируются и ревьюятся.
- [ ] Agent Skills/plugins ревьюятся по description и body; pinned by version/hash.
- [ ] Защита от rug pull: skills/MCP/модели pinned, не `latest`.
- [ ] Если используется внешняя лаборатория оценки — пройден [checklist Evaluation partner](#7-evaluation-partner--внешняя-лаборатория) (или явный N/A).
- [ ] У заказчика независимый kill switch и live telemetry при partner-eval (см. тот же checklist).

## Когда блокировать release

| Событие | Решение |
|---|---|
| secret найден в repo/container | block release |
| critical dependency vuln | block или risk acceptance |
| prompt изменён без review | block release |
| policy ослаблена без owner | block release |
| новый tool без threat model | block release |
| MCP server не в allowlist | block release |
| red team regression failed | block release |
| SBOM не создан | block release для production |
| external eval partner без пройденного checklist | block release / явный N/A с причиной |
| неизвестный model provenance / unpinned model digest | block release |

## Литература

- [Список литературы](../literature.md#стандарты-и-фреймворки) · [Академические исследования](../literature.md#академические-исследования) (model backdoors / triggers)
- [OWASP Agentic AI — Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Practical Guide for Secure MCP Server Development](https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/)
- [SLSA Framework](https://slsa.dev/)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/Projects/ssdf)
- [OpenSSF Scorecard](https://github.com/ossf/scorecard)
- [CycloneDX SBOM Standard](https://cyclonedx.org/)
- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)
- [Taught Well Learned Ill: Distillation-conditional Backdoor](https://arxiv.org/abs/2509.23871)
- [GREAT: RLHF Emotion-Aware Triggers](https://arxiv.org/abs/2510.09260)
- [Enhancing All-to-X Backdoor Attacks](https://arxiv.org/abs/2511.13356)
- [The Trigger in the Haystack](https://arxiv.org/abs/2602.03085)

## См. также

- [10 — Secrets Management](../part-3-processing-security/10-secrets-management.md)
- [08 — Sandboxing (pre-eval / signed scope)](../part-3-processing-security/08-sandboxing.md#sandbox--isolation-containment-escape)
- [13 — Egress Control](../part-4-output-security/13-egress-control-data-exfiltration.md)
- [14 — Human-in-the-Loop](../part-5-control-observability/14-human-in-the-loop.md)
- [19 — MCP Security](../part-6-multi-agent-security/19-mcp-security.md)
- [20 — Red Teaming и Adversarial Testing](20-red-teaming-adversarial-testing.md) (EV-11, Target boundary)
- [21 — Compliance и Standards](21-compliance-standards.md)
- [23 — Incident Response и Recovery](23-incident-response-recovery.md#playbook-autonomous-agent-ir-containment) — TTAC / `evaluation_partner` / notify
- [AI Agent Security Testing Guide](../../guides/ai-agent-security-testing-guide.md) — RoE п.11 Evaluation partner
- [30 — AI Coding Supply Chain](../part-9-ai-coding-security/30-ai-coding-supply-chain.md)
