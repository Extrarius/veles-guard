---
tags: [ai-security, шаблон, course, mcp-review, skills]
статус: шаблон
---

# Course: проверка MCP / навыка (MCP / Skill Review), воркшоп

[← Оглавление](../../README.md)

> Учебная обёртка. Основная форма проверки — [templates/mcp-skill-review.md](../mcp-skill-review.md).  
> Расширенная проверка сервера MCP — [mcp-server-review-template.md](../mcp-server-review-template.md).  
> Воркшоп: [§34](../../notes/part-10-course-appendix/34-mcp-skill-review-workshop.md).

## Как использовать на занятии

1. Выбрать один сервер MCP (MCP server) **или** один навык агента (agent skill) — учебный / из своего проекта.
2. Заполнить [mcp-skill-review.md](../mcp-skill-review.md): кто это (Identity) → возможности (Capabilities) → проверка рисков (Risk checks) → решение (Decision).
3. Сверить с тревожными признаками (red flags) в §34 и примерами [плохо / хорошо (bad-good)](../../examples/course/).
4. Вердикт: **Разрешить (Allow)** / **Отклонить (Reject)** / **Только в песочнице (Sandbox only)** + обязательные ограничения (restrictions).

## Быстрые тревожные признаки (red flags)

- версия (version) = `latest` / «плавающая» (floating)
- install / postinstall / prebuild без объяснения
- скрытые инструкции в описаниях инструментов / навыков (tool / skill descriptions)
- файловая система / сеть / оболочка (filesystem / network / shell) без причины
- нет ответственного (owner) / версии (version) / хеша (hash) / источника (source)
- нет ограничений списка разрешённых инструментов (`allowed-tools`)

## См. также

- [allowed-tools-policy.md](allowed-tools-policy.md)
- [agentic-security-baseline.md](agentic-security-baseline.md)
- [19 — MCP Security](../../notes/part-6-multi-agent-security/19-mcp-security.md)
