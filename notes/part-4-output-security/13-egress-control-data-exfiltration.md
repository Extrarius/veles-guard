---
tags: [ai-security, конспект]
часть: "Часть IV — Защита на выходе"
статус: черновик
---

# 13 — Egress Control и Data Exfiltration Prevention

> Навигация: [Оглавление](../../README.md) · [← Назад](12-hallucination-detection.md) · [Вперёд →](../part-5-control-observability/14-human-in-the-loop.md)

*Кратко: контроль исходящего трафика агента и защита от утечки данных (в т.ч. URL-based exfiltration).*

## Суть

> TODO: что такое egress control и data exfiltration.

## Угроза / контекст

> TODO: утечка данных через ссылки/веб-контент/инструменты, canary tokens.

## Подходы и контрмеры

> TODO: allowlist доменов, контроль сети из sandbox, canary tokens, output filtering, defense in depth.

## Пример (Go)

```go
// TODO: egress allowlist для исходящих запросов агента на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#практические-руководства)

## См. также

- [08 — Sandboxing](../part-3-processing-security/08-sandboxing.md)
- [03 — Prompt Injection Detection](../part-2-input-security/03-prompt-injection-detection.md)
