---
tags: [ai-security, шаблон, course, baseline, mcp, skills]
статус: шаблон
---

# Course: минимальные правила безопасности агента (Agentic Security Baseline), воркшоп

[← Оглавление](../../README.md)

> Учебная обёртка для воркшопа. Основная заполняемая таблица минимальных правил (baseline) — [templates/agentic-security-baseline.md](../agentic-security-baseline.md).  
> Разделы: [§35](../../notes/part-10-course-appendix/35-course-appendix-agentic-security.md) · [§37](../../notes/part-10-course-appendix/37-agentic-security-baseline-workshop.md).

## Как использовать на занятии

1. Открыть заполненный образец [baseline-evidence-filled.md](../../examples/course/baseline-evidence-filled.md) — разобрать, что стоит в Evidence.
2. Скопировать пустую таблицу [agentic-security-baseline.md](../agentic-security-baseline.md).
3. Для правил 2–3–5–6–7–8: сослаться на файл в [baseline-fixtures/](../../examples/course/baseline-fixtures/) или сделать свой мини-файл по тому же образцу. **Yes** только с путём к артефакту.
4. Правила 1 и 4: прогнать [verify-pins.sh](../../examples/bash/verify-pins.sh) и [check-allowed-tools.sh](../../examples/bash/check-allowed-tools.sh) (или зафиксировать «на учебной машине OK» + путь к скрипту).
5. Зафиксировать ответственного (Owner) и дату следующего пересмотра. При Нет (No) по правилам 5 или 6 — не разрешать (Allow) в боевой среде (prod).

Не «прочитай §08 / §13» вместо файла.

## Мини-задание (15 мин)

- [ ] Открыт filled sample; понятно, что Evidence = путь
- [ ] Нет «плавающих» версий (`latest` / floating versions) — Evidence: вывод `verify-pins.sh` или путь к конфигу
- [ ] Есть минимальный список разрешённых инструментов (`allowed-tools`) — Evidence: вывод `check-allowed-tools.sh`
- [ ] Исходящий трафик (egress) закрыт по умолчанию — Evidence: свой json или [egress-allowlist.example.json](../../examples/course/baseline-fixtures/egress-allowlist.example.json)
- [ ] Скрипты / MCP — песочница не от root (non-root sandbox) — Evidence: [sandbox-profile.example.md](../../examples/course/baseline-fixtures/sandbox-profile.example.md) или свой профиль
- [ ] Назначен ответственный (Owner) за минимальные правила (baseline)

## См. также

- [mcp-skill-review.md](mcp-skill-review.md)
- [incident-card-mcp-skill.md](incident-card-mcp-skill.md)
- [examples/course/baseline-evidence-filled.md](../../examples/course/baseline-evidence-filled.md)
- [examples/bash/verify-pins.sh](../../examples/bash/verify-pins.sh)
