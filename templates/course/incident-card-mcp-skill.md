---
tags: [ai-security, шаблон, course, incident, mcp, skills]
статус: шаблон
---

# Course: карточка инцидента (Incident Card) — компрометация MCP / навыка (Skill Compromise)

[← Оглавление](../../README.md)

> Короткая карточка инцидента для воркшопа. Полный отчёт — [incident-report-template.md](../incident-report-template.md).  
> Процесс: [§23 Incident Response](../../notes/part-7-testing-compliance/23-incident-response-recovery.md).

## 1. Сводка

- **Идентификатор инцидента (Incident ID):** `<INC-COURSE-NNN>`
- **Дата / время:** `<YYYY-MM-DD HH:MM TZ>`
- **Критичность (Severity):** `<SEV1 / SEV2 / SEV3>`
- **Тип:** `<отравление навыка (skill poisoning) / отравление инструмента MCP (MCP tool poisoning) / подмена после доверия (rug pull) / цепочка поставок (supply chain) / другое (other)>`
- **Компонент:** `<имя сервера MCP / имя навыка (skill)>` · версия (version) `<зафиксирована (pinned) или неизвестна (unknown)>`

## 2. Что случилось

- **Симптом:** `<...>`
- **Как обнаружено:** `<проверка (review) / CI / сообщение пользователя (user report) / мониторинг (monitoring)>`
- **Затронутые данные / системы:** `<...>`

## 3. Немедленные действия

- [ ] Отключить MCP / навык (skill) — аварийное отключение (kill-switch) / убрать из белого списка (remove from allowlist)
- [ ] Отозвать секреты (secrets), если передавались серверу
- [ ] Зафиксировать версию / хеш / источник (version / hash / source) на момент инцидента
- [ ] Не «чинить» установкой «плавающей» версии (`latest`)

## 4. Корневая причина (root cause), кратко

- **Причина:** `<нет фиксации версии (pin) / нет проверки (review) / скрытые инструкции (hidden instructions) / …>`
- **Какой контроль из минимальных правил (baseline) отсутствовал:** `<правило 1–8>`

## 5. Дальнейшие шаги (follow-up)

- **Ответственный (Owner):** `<...>`
- **Срок:** `<YYYY-MM-DD>`
- **Ссылка на полный отчёт об инциденте (incident report):** `<...>`

## См. также

- [agentic-security-baseline.md](agentic-security-baseline.md)
- [mcp-skill-review.md](mcp-skill-review.md)
