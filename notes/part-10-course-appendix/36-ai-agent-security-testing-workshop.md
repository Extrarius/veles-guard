---
tags: [ai-security, course-appendix, testing, review, workshop, findings]
часть: "Часть X — Учебное приложение"
статус: готово
обновлено: 2026-07-18
изменения: "Первая версия воркшопа: Testing Guide, finding template, валидация полей."
---

# 36 — AI Agent Security Testing Workshop

> Навигация: [Оглавление](../../README.md) · [← Назад](35-agentic-security-baseline-workshop.md) · [Вперёд →](../../README.md)

*Кратко: за 30–45 минут пройти порядок проверки своего агента — Scope и Rules of Engagement, 3–4 строки Test Matrix, 1–2 finding, краткий Report; без offensive payloads.*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-10/36-ai-agent-security-testing-workshop.py) ·
> [Bash](../../examples/bash/part-10/36-ai-agent-security-testing-workshop.sh) ·
> [TypeScript](../../examples/typescript/part-10/36-ai-agent-security-testing-workshop.ts) ·
> [C++](../../examples/cpp/part-10/36-ai-agent-security-testing-workshop.cpp) ·
> [Java](../../examples/java/part-10/36-ai-agent-security-testing-workshop.java)

## Суть

После review одного MCP/skill ([§34](34-mcp-skill-review-workshop.md)) и baseline среды ([§35](35-agentic-security-baseline-workshop.md)) нужен **порядок проверки агента целиком**: что входит в scope, какие границы, как фиксировать finding и куда положить regression.

Канон процесса (не дублируем здесь):

- [guides/ai-agent-security-testing-guide.md](../../guides/ai-agent-security-testing-guide.md)

Формы:

- Обёртка для воркшопа: [templates/course/agent-security-finding.md](../../templates/course/agent-security-finding.md)
- Основная карточка finding: [templates/agent-security-finding.md](../../templates/agent-security-finding.md)

Связь с теорией: [§20](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md) (adversarial testing), [§23](../part-7-testing-compliance/23-incident-response-recovery.md) (если finding = инцидент), [§25](../part-8-practice/25-security-by-design-checklist.md) / [§32](../part-9-ai-coding-security/32-ai-coding-security-checklist.md) (чеклисты).

## Для кого

| Роль | Как использовать |
|---|---|
| Преподаватель | Практикум 30–45 мин после §34/§35 |
| Студент | Первый security review своего агента / учебного sandbox |
| Разработчик | Обвязка «прочитал конспект → проверил систему» |
| Команда | Единый язык findings и severity перед prod |

## Что НЕ является целью

Воркшоп **не** предназначен для:

- публикации рабочих вредоносных нагрузок (offensive payloads);
- обхода чужих сервисов или внешних MCP;
- «пентеста» инфраструктуры вне согласованного sandbox.

Все проверки — учебные и позитивные: убедиться, что контроль **срабатывает**.

## Угроза / контекст

Типичный разрыв после теории:

```text
прочитали §20 / §25 / §32
  → нет единого Scope / RoE
  → findings «устно»
  → нет regression
  → тот же баг на prod
```

Гайд и этот воркшоп закрывают вопрос: *как проверить своего агента по шагам*.

## План воркшопа (outline), 30–45 мин

| Мин | Тема | Что сделать |
|---|---|---|
| 0–5 | Scope + RoE | Прочитать §1–2 гайда; зафиксировать out-of-scope |
| 5–15 | Test Matrix | Выбрать 3–4 строки под свой агент; для каждой — Expected |
| 15–30 | Findings | Заполнить 1–2 карточки; Critical/High → Fix + Regression |
| 30–40 | Report | Summary, high-risk, blocked, checklist / red-team updates |
| 40–45 | Mapping | Привязать findings к §20 / §23 / §25 / §32 (и узким разделам) |

## Подходы и контрмеры

### Минимальный проход

1. Согласовать Scope (что тестируем) и RoE (чего не делаем).
2. Взять строки matrix: например Tools, Egress, MCP, AI-coding — или релевантные вашему агенту.
3. Формулировки только вида: «проверить, что агент НЕ… / что контроль блокирует…».
4. Evidence без секретов; destructive — только mock tools.
5. Не закрывать Critical/High без Regression test (правило §20).

### Severity (шпаргалка)

| Severity | Пример на воркшопе |
|---|---|
| Critical | sandbox escape, успешный egress вне allowlist |
| High | tool call без approval; секрет в output |
| Medium | нет trace на dangerous tool при иных компенсациях |
| Low | нет owner в inventory при низком риске |

## Пример (Go): валидация обязательных полей finding

Иллюстрация: finding не принимают без Area, Severity и Regression для Critical/High.

```go
package finding

import "fmt"

type Severity string

const (
	Critical Severity = "Critical"
	High     Severity = "High"
	Medium   Severity = "Medium"
	Low      Severity = "Low"
)

type Area string

const (
	AreaTools   Area = "tools"
	AreaEgress  Area = "egress"
	AreaSandbox Area = "sandbox"
	AreaMCP     Area = "MCP"
	// … input, context, memory, output, AI-coding
)

type Finding struct {
	ID             string
	Title          string
	Severity       Severity
	Area           Area
	Expected       string
	Actual         string
	Fix            string
	RegressionTest string
}

func Validate(f Finding) error {
	if f.ID == "" || f.Title == "" {
		return fmt.Errorf("id and title required")
	}
	if f.Area == "" || f.Severity == "" {
		return fmt.Errorf("area and severity required")
	}
	if f.Expected == "" || f.Actual == "" {
		return fmt.Errorf("expected and actual required")
	}
	if (f.Severity == Critical || f.Severity == High) && f.RegressionTest == "" {
		return fmt.Errorf("%s finding requires regression test", f.Severity)
	}
	return nil
}
```

Полные порты — в `examples/*/part-10/36-ai-agent-security-testing-workshop.*`.

### Упражнение (15 мин)

1. Открыть [Testing Guide](../../guides/ai-agent-security-testing-guide.md) и course-обёртку finding.
2. Выбрать 3 строки matrix.
3. Оформить один High finding (можно учебный: «tool X вызывается без approval в mock»).
4. Указать Regression test (имя кейса / CI job) и handbook ref (`§14` / `§20` / …).
5. В Report одной фразой: blocked или нет для prod.

## Чек-лист

- [ ] Scope и RoE понятны участникам
- [ ] Выбраны 3–4 строки Test Matrix
- [ ] Заполнены 1–2 finding по шаблону
- [ ] Critical/High имеют Fix и Regression test
- [ ] Есть краткий Report (summary + blocked + updates)
- [ ] Findings смаплены на §20 / §23 / §25 / §32 (или узкие разделы)

## Литература

- [Список литературы](../literature.md)
- Процесс: [AI Agent Security Testing Guide](../../guides/ai-agent-security-testing-guide.md)
- Конспект: [§20](../part-7-testing-compliance/20-red-teaming-adversarial-testing.md), [§23](../part-7-testing-compliance/23-incident-response-recovery.md), [§25](../part-8-practice/25-security-by-design-checklist.md), [§32](../part-9-ai-coding-security/32-ai-coding-security-checklist.md)

## См. также

- [33 — Course Appendix](33-course-appendix-agentic-security.md)
- [34 — MCP / Skill Review Workshop](34-mcp-skill-review-workshop.md)
- [35 — Agentic Security Baseline Workshop](35-agentic-security-baseline-workshop.md)
- [templates/agent-security-finding.md](../../templates/agent-security-finding.md)
