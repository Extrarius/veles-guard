---
tags: [ai-security, конспект]
часть: "Часть VI — Мультиагентная безопасность"
статус: черновик
---

# 18 — Inter-Agent Security

> Навигация: [Оглавление](../../README.md) · [← Назад](../part-5-control-observability/17-circuit-breaker-kill-switch.md) · [Вперёд →](19-mcp-security.md)

*Кратко: mTLS, подпись сообщений и проверка идентичности между агентами.*

## Суть

> TODO: безопасность межагентного взаимодействия, границы доверия.

## Угроза / контекст

> TODO: insecure inter-agent communication, подделка сообщений, delegation-атаки.

## Подходы и контрмеры

> TODO: mTLS, message signing / HMAC, agent identity verification, trust boundaries.

## Пример (Go)

```go
// TODO: gRPC с mutual TLS между агентами на Go
```

## Чек-лист

- [ ] TODO

## Литература

- [Список литературы](../literature.md#стандарты-и-фреймворки)

## См. также

- [19 — MCP Security](19-mcp-security.md)
- [02 — Модель угроз (Threat Model)](../part-1-architecture-threats/02-threat-model.md)
