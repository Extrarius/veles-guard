---
tags: [ai-security, course-appendix, mcp, skills, review, workshop]
часть: "Часть X — Учебное приложение"
статус: готово
обновлено: 2026-07-18
изменения: "Добавлены ссылки на примеры TypeScript, C++ и Java (part-10)."
---

# 34 — MCP / Skill Review Workshop

> Навигация: [Оглавление](../../README.md) · [← Назад](33-course-appendix-agentic-security.md) · [Вперёд →](35-agentic-security-baseline-workshop.md)

*Кратко: как за 15–20 минут провести проверку безопасности (security review) сервера MCP или навыка агента (agent skill) — поля формы, тревожные признаки (red flags), учебные «плохо / хорошо» (bad / good), вердикт: разрешить (Allow) / отклонить (Reject) / только в песочнице (Sandbox only).*

> Примеры в разделе — на Go. Те же примеры на других языках:
> [Python](../../examples/python/part-10/34-mcp-skill-review-workshop.py) ·
> [Bash](../../examples/bash/part-10/34-mcp-skill-review-workshop.sh) ·
> [TypeScript](../../examples/typescript/part-10/34-mcp-skill-review-workshop.ts) ·
> [C++](../../examples/cpp/part-10/34-mcp-skill-review-workshop.cpp) ·
> [Java](../../examples/java/part-10/34-mcp-skill-review-workshop.java)

## Суть

Перед подключением MCP или навыка (skill) нужен явный шлюз проверки (review gate). Не «установили из каталога (registry) и поехали», а:

1. Кто это (Identity) — кто / что / какая версия.
2. Возможности (Capabilities) — какие инструменты (tools), файловая система (FS), сеть (network), командная оболочка (shell), секреты (secrets).
3. Проверка рисков (Risk checks) — тревожные признаки (red flags) и доказательства (evidence).
4. Решение (Decision) — разрешить (Allow) / отклонить (Reject) / только в песочнице (Sandbox only) + ограничения (restrictions).

Формы:

- Обёртка для воркшопа: [templates/course/mcp-skill-review.md](../../templates/course/mcp-skill-review.md)
- Основная (каноническая) форма: [templates/mcp-skill-review.md](../../templates/mcp-skill-review.md)
- Расширенная проверка сервера MCP: [templates/mcp-server-review-template.md](../../templates/mcp-server-review-template.md)

## Угроза / контекст

| Вектор | Симптом | Контроль |
|---|---|---|
| Отравление описания инструмента / навыка (tool / skill description poisoning) | Скрытые инструкции в описании (description) | Проверка (review) текста + недоверие к метаданным (metadata) ([§19](../part-6-multi-agent-security/19-mcp-security.md)) |
| Цепочка поставок / «подмена после доверия» (supply chain / rug pull) | `latest`, смена поведения (behavior) без фиксации версии (pin) | Фиксация версии (pin) + хеш (hash) + повторная проверка (re-review) |
| Установка с лишними правами (over-privileged install) | postinstall / curl\|bash | Запрет необъяснённых скриптов (scripts); песочница (sandbox) |
| Разрастание возможностей (capability creep) | Файлы / сеть / shell «на всякий случай» | Минимальные права (least privilege) + [политика разрешённых инструментов (allowed-tools policy)](../../templates/course/allowed-tools-policy.md) |
| Нет владельца | неизвестный ответственный (unknown owner) | Отклонить (Reject), пока не назначен ответственный (Owner) |

## Подходы и контрмеры

### Поля проверки (минимум)

**Кто это (Identity)**

- имя (name), версия (version, зафиксированная / pinned), источник (source), хеш / происхождение (hash / provenance), ответственный (owner)

**Возможности (Capabilities)**

- список инструментов (tools); пути файловой системы (filesystem paths); сеть (network); оболочка (shell); доступ к секретам (secrets); хуки установки (install hooks)

**Проверка рисков (Risk checks)**

- [ ] нет «плавающей» версии (`latest` / floating)
- [ ] нет необъяснённых шагов install / postinstall / prebuild
- [ ] описание (description) без скрытых инструкций
- [ ] файлы (FS) / сеть (network) / shell обоснованы задачей
- [ ] есть ответственный (owner), версия (version), хеш / источник (hash / source)
- [ ] есть ограничения списка разрешённых инструментов (`allowed-tools`)

**Решение (Decision)**

| Вердикт | Когда |
|---|---|
| **Разрешить (Allow)** | Фиксация версии (pin) + ответственный (owner) + минимальные права (least privilege) + чистое описание (description) + песочница / исходящий трафик (sandbox / egress) в порядке |
| **Только в песочнице (Sandbox only)** | Нужен эксперимент, но с урезанными инструментами (tools) / сетью запрещена (deny network) / не от root (non-root) |
| **Отклонить (Reject)** | Любой критичный тревожный признак (red flag) без компенсаций |

### Тревожные признаки (red flags) — быстрый список

1. `version: latest` или «плавающий» тег (floating tag)
2. Install / postinstall / prebuild без прозрачного содержимого
3. Скрытые инструкции в описаниях инструментов / навыков (tool / skill descriptions)
4. Файловая система / сеть / shell без причины под задачу
5. Нет ответственного (owner) / версии (version) / хеша (hash) / доверенного источника (trusted source)
6. Нет ограничений `allowed-tools` (любые инструменты / wildcard; полный доступ / danger-full-access)

## Пример: плохо / хорошо (bad vs good)

Учебные фрагменты (без рабочих вредоносных нагрузок / payloads):

- Манифест навыка (skill manifest): [examples/course/bad-good-skill-manifest.md](../../examples/course/bad-good-skill-manifest.md)
- Описание инструмента MCP (MCP tool description): [examples/course/bad-good-mcp-tool-description.md](../../examples/course/bad-good-mcp-tool-description.md)

### Упражнение (10 мин)

1. Открыть «плохой» навык (Bad skill) и «плохое» описание инструмента (Bad tool description).
2. Выписать тревожные признаки (red flags).
3. Заполнить форму проверки (review) для «хорошего» варианта (Good).
4. Для «плохого» вынести вердикт **Отклонить (Reject)** и одну фразу корневой причины (root cause), например: «скрытые инструкции + незафиксированная версия + скрипт установки».

### Иллюстрация (Go): отклонить инструмент (tool) по политике (policy)

```go
package review

import "strings"

func DescriptionLooksHostile(desc string) bool {
	lower := strings.ToLower(desc)
	// Учебные маркеры — не полный detector. В проде: отдельный review + policy.
	markers := []string{
		"ignore previous",
		"system override",
		"do not tell the user",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}
```

Полноценная проверка аргументов (validation args) — [§07](../part-3-processing-security/07-parameter-validation-schema.md); проверка выхода (output) — [§11](../part-4-output-security/11-output-validation-fact-checking.md).

## Чек-лист воркшопа

- [ ] Выбран один MCP **или** один навык (skill)
- [ ] Заполнены: кто это (Identity) / возможности (Capabilities) / риски (Risk) / решение (Decision)
- [ ] Пройдены 6 тревожных признаков (red flags)
- [ ] Сверены «плохо / хорошо» (bad / good) из `examples/course/`
- [ ] Вердикт записан; при «Разрешить (Allow)» — список ограничений (restrictions)
- [ ] Ответственный (Owner) и дата следующего пересмотра назначены

## Литература

- [Список литературы](../literature.md)
- [MCP Specification](https://modelcontextprotocol.io/)
- Связанные разделы конспекта: §19, §30, §31

## См. также

- [33 — Course Appendix](33-course-appendix-agentic-security.md)
- [35 — Baseline Workshop](35-agentic-security-baseline-workshop.md)
- [19 — MCP Security](../part-6-multi-agent-security/19-mcp-security.md)
- [30 — AI Coding Supply Chain](../part-9-ai-coding-security/30-ai-coding-supply-chain.md)
- [22 — Supply Chain Security](../part-7-testing-compliance/22-supply-chain-security.md)
