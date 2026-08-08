---
tags: [ai-security, output-validation, fact-checking, guardrails, output-security, конспект]
часть: "Часть IV — Защита на выходе"
статус: готово
обновлено: 2026-08-05
изменения: "Streaming output guardrail: проверка по чанкам, stream_first vs validate_first, StreamChunkGuard."
---

# 11 — Output Validation и Fact-Checking

> Навигация: [Оглавление](../../README.md) · [← Назад](../part-3-processing-security/10-secrets-management.md) · [Вперёд →](12-hallucination-detection.md)

*Кратко: выход модели нельзя считать доверенным. Перед показом пользователю или передачей в другой компонент ответ нужно проверить: формат, безопасность, ссылки на источники, отсутствие секретов, корректность действий и соответствие политике.*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-4/11-output-validation-fact-checking.py) ·
> [TypeScript](../../examples/typescript/part-4/11-output-validation-fact-checking.ts)

## Суть

**Output Validation** — это слой проверки ответа агента перед тем, как он попадёт:

- пользователю;
- в браузер / HTML / Markdown renderer;
- в API другого сервиса;
- в базу данных;
- в tool другого агента;
- в лог / trace / отчёт;
- в цепочку автоматического действия.

Главное правило:

```text
Ответ LLM — это недоверенный выход.
Его нельзя напрямую выполнять, рендерить, сохранять или передавать дальше.
```

В обычном чат-боте плохой ответ чаще всего означает неправильный текст. В агенте плохой ответ может стать:

- аргументом следующего tool call;
- HTML/JS, который попадёт в интерфейс;
- SQL/командой/скриптом;
- письмом клиенту;
- решением об оплате, удалении, отправке, публикации;
- источником для другого агента.

Поэтому output validation — это не “красивый финальный фильтр”, а **граница безопасности между моделью и внешним миром**.

Выходной gate — зеркальный layered path к входному [guardrail pipeline §03](../part-2-input-security/03-prompt-injection-detection.md#guardrail-pipeline-router): эвристики / schema → filter (PII, secrets, safety) → более тяжёлые проверки. Validation полного ответа до выпуска за Output Gate — канон ниже; для SSE/token stream дополнительно — [проверка по чанкам](#streaming-output-guardrail).

## Что проверяем на выходе

| Тип выхода | Что может пойти не так | Контроль |
|---|---|---|
| Текстовый ответ | секреты, PII, вредные инструкции, галлюцинации | redaction, policy check, fact-checking |
| JSON / structured output | неверная схема, лишние поля, опасные значения | strict schema, allowlist, reject unknown fields |
| Markdown / HTML | XSS, скрытые ссылки, tracking, phishing | escaping, sanitization, safe renderer |
| URL | SSRF, phishing, exfiltration endpoint | URL allowlist, domain policy |
| Code / shell / SQL | RCE, data loss, privilege abuse | never auto-execute, sandbox, review |
| Tool result summary | искажение результата tool | compare with raw observation |
| Citation / source | выдуманная ссылка, неверная цитата | source verification |
| Business decision | ошибочное approve/reject | human-in-the-loop, threshold |

**Граница с Parameter Validation (§07).** Аргументы tool call / function-calling JSON проверяются в [§07](../part-3-processing-security/07-parameter-validation-schema.md) — до executor. Здесь (§11) — ответ модели как выход: текст, `structured_json` для UI/API, HTML/Markdown, citations. Schema на входе в tool не заменяет schema на выходе к пользователю или downstream.

## DFD: output validation layer

```mermaid
flowchart LR
    Planner[Process: LLM Planner] -->|raw answer| OutputPolicy[Process: Output Policy]

    OutputPolicy --> SchemaValidator[Process: Schema Validator]
    OutputPolicy --> SafetyFilter[Process: Safety / PII / Secret Filter]
    OutputPolicy --> FactChecker[Process: Fact Checker]
    OutputPolicy --> Renderer[Process: Safe Renderer]

    Evidence[(Data Store: Evidence / Tool Observations / Sources)] --> FactChecker

    SchemaValidator --> Decision{Allow?}
    SafetyFilter --> Decision
    FactChecker --> Decision
    Renderer --> Decision

    Decision -->|allow| User[External Entity: User]
    Decision -->|allow structured| Downstream[External System: Downstream API]
    Decision -->|block / needs review| Review[Process: Human Review]

    Review --> User
```

## Trust boundary

```text
Trust Boundary: Agent Runtime
  LLM Planner
  Tool Observations
  Internal State

Trust Boundary: Output Gate
  Schema validation
  Safety filtering
  Fact-checking
  Redaction
  Rendering policy

Trust Boundary: External World
  User
  Browser
  APIs
  Files
  Logs
  Other agents
```

Ключевая идея:

```text
Сырые ответы LLM не пересекают границу Output Gate без проверки.
```

## Угроза / контекст

| Угроза | Пример | Risk | Контроль |
|---|---|---:|---|
| Improper Output Handling | модель вернула HTML, который напрямую отрисован в браузере | High | escaping, sanitizer, CSP |
| Data leak | ответ содержит token, email, внутренние ID, персональные данные | High | secret/PII redaction |
| Hallucinated fact | агент уверенно пишет неподтверждённый факт | High | claim verification, citations |
| Fake citation | модель ссылается на несуществующий документ | Medium | citation resolver |
| Action laundering | опасное действие замаскировано как “рекомендация” | High | action classifier, approval |
| Tool result distortion | агент неправильно пересказал результат API | Medium | compare summary with raw observation |
| Format confusion | downstream ждёт JSON, получает текст с лишними полями | Medium | strict schema |
| Prompt leakage | модель раскрывает system/developer instructions | High | output policy, no prompt exposure |
| Phishing link | агент предлагает перейти на похожий домен | Medium | URL allowlist |
| Log contamination | ответ с секретом попадает в trace | High | redacted logging |
| Partial stream leak | `stream_first`: rail блокирует поздно, клиент уже получил префикс (секрет / XSS / инструкция) | High | `validate_first` для high-risk; hard stop + audit уже отданного |

## Связь с OWASP / NIST

| Контроль | Связанный риск |
|---|---|
| Output validation | OWASP LLM05: Improper Output Handling |
| Secret / PII redaction | OWASP LLM02: Sensitive Information Disclosure |
| Fact-checking | OWASP LLM09: Misinformation |
| Human approval для опасных действий | OWASP LLM06: Excessive Agency |
| Test/evaluation/verification/validation | NIST AI RMF: TEVV throughout lifecycle |

## Подходы и контрмеры

### 1. Разделять типы выхода

Не все ответы одинаковы.

```text
final_text      → показать пользователю
structured_json → передать в API
tool_args       → отправить executor'у
html            → отрендерить в UI
code            → показать как текст, но не выполнять
```

Для каждого типа нужен свой policy.

### 2. Использовать allowlist, а не blacklist

Плохо:

```text
Запретить несколько опасных слов.
```

Лучше:

```text
Разрешить только ожидаемый формат, ожидаемые поля и ожидаемые типы значений.
```

### 3. Не выполнять output напрямую

```text
LLM output ≠ command
LLM output ≠ SQL
LLM output ≠ HTML
LLM output ≠ trusted JSON
```

Даже если модель “должна была” вернуть безопасный JSON, его всё равно нужно разобрать strict parser'ом и проверить.

### 4. Проверять утверждения отдельно от стиля

Красивый и уверенный ответ не означает правильный ответ.

Минимальный процесс:

```text
answer → extract claims → verify against evidence → mark unsupported → rewrite/block
```

### 5. Сохранять evidence trail

Если ответ основан на tool calls или документах, у ответа должен быть след:

```text
claim → source/tool observation → timestamp → confidence/status
```

Это нужно для аудита, incident response и red teaming.

## Go snippet: output validation pipeline

```go
package outputsec

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type OutputKind string

const (
	OutputFinalText  OutputKind = "final_text"
	OutputStructured OutputKind = "structured_json"
	OutputHTML       OutputKind = "html"
	OutputCode       OutputKind = "code"
)

type Output struct {
	Kind    OutputKind
	Text    string
	Meta    map[string]string
	Sources []SourceRef
}

type SourceRef struct {
	ID    string
	Title string
	URL   string
}

type ValidationResult struct {
	Allowed bool
	Reason  string
	Risk    string // High / Medium / Low
}

type Validator interface {
	Validate(ctx context.Context, out Output) ValidationResult
}

type Pipeline struct {
	Validators []Validator
}

func (p Pipeline) Validate(ctx context.Context, out Output) error {
	for _, v := range p.Validators {
		res := v.Validate(ctx, out)
		if !res.Allowed {
			return fmt.Errorf("output blocked: %s risk=%s", res.Reason, res.Risk)
		}
	}
	return nil
}

type SecretLeakValidator struct{}

func (SecretLeakValidator) Validate(ctx context.Context, out Output) ValidationResult {
	text := strings.ToLower(out.Text)
	markers := []string{"api_key", "authorization:", "bearer ", "password=", "secret="}
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return ValidationResult{Allowed: false, Reason: "possible secret leak", Risk: "High"}
		}
	}
	return ValidationResult{Allowed: true}
}

type HTMLPolicyValidator struct{}

func (HTMLPolicyValidator) Validate(ctx context.Context, out Output) ValidationResult {
	if out.Kind != OutputHTML {
		return ValidationResult{Allowed: true}
	}

	lower := strings.ToLower(out.Text)
	disallowed := []string{"<script", "javascript:", "onerror=", "onclick=", "<iframe"}
	for _, token := range disallowed {
		if strings.Contains(lower, token) {
			return ValidationResult{Allowed: false, Reason: "unsafe html output", Risk: "High"}
		}
	}

	return ValidationResult{Allowed: true}
}

type SourceRequiredValidator struct{}

func (SourceRequiredValidator) Validate(ctx context.Context, out Output) ValidationResult {
	if out.Meta["requires_sources"] != "true" {
		return ValidationResult{Allowed: true}
	}
	if len(out.Sources) == 0 {
		return ValidationResult{Allowed: false, Reason: "answer requires sources but none provided", Risk: "Medium"}
	}
	return ValidationResult{Allowed: true}
}

func Publish(ctx context.Context, p Pipeline, out Output) error {
	if out.Text == "" {
		return errors.New("empty output")
	}
	return p.Validate(ctx, out)
}
```

Главная мысль:

```text
Публикация ответа — отдельная операция.
Перед ней output проходит validators.
```

## Go snippet: safe structured output

```go
package outputsec

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type CustomerMessage struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
	Tone    string `json:"tone"`
}

func ParseCustomerMessage(raw []byte) (CustomerMessage, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()

	var msg CustomerMessage
	if err := dec.Decode(&msg); err != nil {
		return CustomerMessage{}, fmt.Errorf("invalid structured output: %w", err)
	}

	if msg.Subject == "" || msg.Body == "" {
		return CustomerMessage{}, errors.New("subject and body are required")
	}

	allowedTone := map[string]bool{
		"neutral": true,
		"formal":  true,
		"friendly": true,
	}
	if !allowedTone[msg.Tone] {
		return CustomerMessage{}, fmt.Errorf("unsupported tone: %q", msg.Tone)
	}

	if strings.Contains(strings.ToLower(msg.Body), "password") {
		return CustomerMessage{}, errors.New("message may contain sensitive data")
	}

	return msg, nil
}
```

## Go snippet: проверка ссылок на источники

```go
package outputsec

type EvidenceStore interface {
	Exists(sourceID string) bool
	AllowedForUser(userID, sourceID string) bool
}

func ValidateSources(userID string, sources []SourceRef, store EvidenceStore) error {
	for _, s := range sources {
		if s.ID == "" {
			return errors.New("source id is required")
		}
		if !store.Exists(s.ID) {
			return fmt.Errorf("unknown source: %s", s.ID)
		}
		if !store.AllowedForUser(userID, s.ID) {
			return fmt.Errorf("source is not allowed for user: %s", s.ID)
		}
	}
	return nil
}
```

## Практический шаблон output policy

```yaml
output_policy:
  default: block_if_uncertain
  final_text:
    pii_redaction: true
    secret_redaction: true
    require_sources_for_factual_claims: true
  html:
    allow_raw_html: false
    render_as_text: true
  structured_json:
    strict_schema: true
    reject_unknown_fields: true
  code:
    auto_execute: false
    require_human_review: true
  external_links:
    allowlist_domains:
      - docs.example.com
      - support.example.com
```

<a id="streaming-output-guardrail"></a>

## Streaming output guardrail

При SSE / token stream полный `Validate` до первого токена ломает UX. Без проверки по пути клиент уже получает сырой выход — и обрыв после block не откатывает отданное.

```text
Полный ответ ≠ достаточно для streaming UX.
Проверяй окно чанков на пути к клиенту; Output Gate на собранном ответе остаётся обязательным.
```

### Модель буфера

1. Накапливать токены до `chunk_size`.
2. Окно проверки = хвост предыдущего чанка (`context_size`) + новый чанк — иначе секрет/PII/XSS рвётся на границе.
3. В горячем пути чанка — детерминированные эвристики (secrets, PII patterns, stop-patterns). Тяжёлый LLM-as-judge — вне per-chunk path (на полном ответе или асинхронно).

Ориентир параметров и режимов: [NVIDIA NeMo Guardrails — Output Rail Streaming](https://docs.nvidia.com/nemo/guardrails/configure-guardrails/yaml-schema/streaming/output-rail-streaming) (`chunk_size`, `context_size`, `stream_first`).

### Режимы: `stream_first` vs `validate_first`

| Режим | Порядок | Latency (TTFT) | Риск |
|---|---|---|---|
| `stream_first` | отдать чанк клиенту → rail на окне; при block — оборвать stream | ниже | клиент уже видел префикс |
| `validate_first` | rail на окне → отдать только если ok | выше на время rail | blocked content не уходит клиенту |

**Правило выбора**

```text
Секреты / HTML / business-decision / regulated → validate_first (или не stream наружу).
Low-risk chat → stream_first допустим, если есть hard stop stream + audit уже отданного префикса.
```

Streaming rail **не заменяет** Output Gate: schema, fact-check, citations — на полном ответе (или после сборки stream). Связка с входным layered path — [§03 Guardrail pipeline](../part-2-input-security/03-prompt-injection-detection.md#guardrail-pipeline-router).

### Go snippet: streaming chunk guard

```go
package outputval

import "fmt"

type StreamMode string

const (
	StreamFirst   StreamMode = "stream_first"
	ValidateFirst StreamMode = "validate_first"
)

type StreamChunkGuard struct {
	ChunkSize   int
	ContextSize int
	Mode        StreamMode
	// CheckWindow — детерминированная проверка окна (secrets / PII / stop-patterns).
	// Тяжёлый judge — вне горячего пути чанка.
	CheckWindow func(window string) error

	buf     string
	context string
}

// Feed накапливает токены; emit — текст к клиенту (может быть ""); stop — оборвать stream.
func (g *StreamChunkGuard) Feed(token string) (emit string, stop bool, err error) {
	if g.ChunkSize <= 0 {
		return "", true, fmt.Errorf("chunk_size must be > 0")
	}
	g.buf += token
	if len(g.buf) < g.ChunkSize {
		return "", false, nil
	}
	return g.flushChunk()
}

// Flush остаток буфера в конце stream (вызывать после последнего токена).
func (g *StreamChunkGuard) Flush() (emit string, stop bool, err error) {
	if g.buf == "" {
		return "", false, nil
	}
	return g.flushChunk()
}

func (g *StreamChunkGuard) flushChunk() (string, bool, error) {
	chunk := g.buf
	g.buf = ""
	window := g.context + chunk

	switch g.Mode {
	case StreamFirst:
		// Сначала отдать чанк, затем rail — при block клиент уже видел префикс.
		g.advanceContext(chunk)
		if err := g.CheckWindow(window); err != nil {
			return chunk, true, err
		}
		return chunk, false, nil
	case ValidateFirst:
		if err := g.CheckWindow(window); err != nil {
			return "", true, err
		}
		g.advanceContext(chunk)
		return chunk, false, nil
	default:
		return "", true, fmt.Errorf("unknown stream mode: %s", g.Mode)
	}
}

func (g *StreamChunkGuard) advanceContext(chunk string) {
	if g.ContextSize <= 0 {
		g.context = ""
		return
	}
	g.context += chunk
	if len(g.context) > g.ContextSize {
		g.context = g.context[len(g.context)-g.ContextSize:]
	}
}
```

В режиме `stream_first` при ошибке `CheckWindow` чанк уже уходит клиенту (`emit` + `stop`) — вызывающий обязан оборвать stream и записать audit префикса. В `validate_first` при block `emit` пустой.

## Чек-лист

- [ ] Сырые ответы LLM не передаются напрямую пользователю или downstream-системам.
- [ ] Для structured output используется strict schema.
- [ ] Unknown fields запрещены.
- [ ] HTML/Markdown проходит безопасный renderer/sanitizer.
- [ ] Секреты и PII редактируются до публикации и логирования.
- [ ] Фактические утверждения проверяются по evidence/source.
- [ ] Ссылки на источники проверяются на существование и доступность пользователю.
- [ ] Код/SQL/shell-команды не выполняются автоматически.
- [ ] Ответы, влияющие на бизнес-действия, требуют approval.
- [ ] Есть audit trail: prompt, tool observations, output, validation decision.
- [ ] Для streaming UX есть path с `chunk_size` + `context_size` (окно не рвёт секреты/PII на границе чанка).
- [ ] Режим `stream_first` / `validate_first` выбран явно под класс риска выхода.
- [ ] При `stream_first` есть hard stop stream и audit уже отданного префикса; schema/fact-check — на полном ответе.

## Литература

- [Список литературы](../literature.md#практические-руководства) — [NVIDIA NeMo Guardrails](../literature.md#практические-руководства)
- [NVIDIA NeMo Guardrails — Output Rail Streaming](https://docs.nvidia.com/nemo/guardrails/configure-guardrails/yaml-schema/streaming/output-rail-streaming) — `chunk_size`, `context_size`, `stream_first`
- [OWASP LLM05:2025 Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)
- [OWASP LLM02:2025 Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/)
- [OWASP LLM09:2025 Misinformation](https://genai.owasp.org/llmrisk/llm092025-misinformation/)
- [OpenAI Cookbook — Developing Hallucination Guardrails](https://developers.openai.com/cookbook/examples/developing_hallucination_guardrails)
- [NIST AI Risk Management Framework 1.0](https://www.nist.gov/itl/ai-risk-management-framework)

## См. также

- [03 — Prompt Injection Detection](../part-2-input-security/03-prompt-injection-detection.md#guardrail-pipeline-router) — входной layered path; выход зеркален
- [04 — PII Redaction и Content Filtering](../part-2-input-security/04-pii-redaction-content-filtering.md)
- [07 — Parameter Validation и Schema Enforcement](../part-3-processing-security/07-parameter-validation-schema.md)
- [10 — Secrets Management](../part-3-processing-security/10-secrets-management.md)
- [12 — Hallucination Detection](12-hallucination-detection.md)
- [14 — Human-in-the-Loop](../part-5-control-observability/14-human-in-the-loop.md)
