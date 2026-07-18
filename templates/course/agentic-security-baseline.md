---
tags: [ai-security, шаблон, course, baseline, mcp, skills]
статус: шаблон
---

# Course: минимальные правила безопасности агента (Agentic Security Baseline), воркшоп

[← Оглавление](../../README.md)

> Учебная обёртка для воркшопа. Основная заполняемая таблица минимальных правил (baseline) — [templates/agentic-security-baseline.md](../agentic-security-baseline.md).  
> Разделы: [§33](../../notes/part-10-course-appendix/33-course-appendix-agentic-security.md) · [§35](../../notes/part-10-course-appendix/35-agentic-security-baseline-workshop.md).

## Как использовать на занятии

1. Открыть [agentic-security-baseline.md](../agentic-security-baseline.md).
2. Пройти 8 правил со статусами Да / Частично / Нет / Не применимо (Yes / Partial / No / N/A) для своего агента / MCP / навыка (skill).
3. Зафиксировать ответственного (Owner) и дату следующего пересмотра.
4. Связать с [allowed-tools-policy.md](allowed-tools-policy.md) и проверками в CI из [examples/github-actions/agent-security.example.yml](../../examples/github-actions/agent-security.example.yml).

## Мини-задание (15 мин)

- [ ] Нет «плавающих» версий (`latest` / floating versions)
- [ ] Есть минимальный список разрешённых инструментов (`allowed-tools`)
- [ ] Исходящий трафик (egress) закрыт по умолчанию — белый список (allowlist)
- [ ] Скрипты / MCP — песочница не от root (non-root sandbox)
- [ ] Назначен ответственный (Owner) за минимальные правила (baseline)

## См. также

- [mcp-skill-review.md](mcp-skill-review.md)
- [incident-card-mcp-skill.md](incident-card-mcp-skill.md)
- [examples/bash/verify-pins.sh](../../examples/bash/verify-pins.sh)
