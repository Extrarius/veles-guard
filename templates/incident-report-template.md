---
tags: [ai-security, шаблон, incident]
статус: шаблон
---

# Шаблон: Incident Report

[← Оглавление](../README.md)

> Заполняемая форма для разбора инцидента с AI-агентом. Процесс — в [23 — Incident Response и Recovery](../notes/part-7-testing-compliance/23-incident-response-recovery.md).

## 1. Сводка

- **Incident ID:** `<INC-YYYY-NNN>`
- **Дата обнаружения:** `<YYYY-MM-DD HH:MM TZ>`
- **Severity:** `<SEV1 / SEV2 / SEV3>`
- **Тип:** `<prompt injection / exfiltration / tool misuse / supply chain / containment escape / autonomous agent / DoS / прочее>`
- **Статус:** `<active / contained / resolved>`
- **Автор отчёта:** `<...>`

## 2. Обнаружение

- **Как обнаружено:** `<алерт / пользователь / аудит логов>`
- **Источник сигнала:** `<monitoring / trace / внешний репорт>`
- **Первый признак:** `<...>`
- **Detection signal(s):** `<egress_destination_out_of_policy / eval_probe_suspected / tool_retry_after_deny / credential_use_after_revoke / score_spike_after_network / undeclared_tool_call / audit_gap / …>`

## 3. Timeline

| Время (UTC) | Событие |
|---|---|
| `<HH:MM>` | `<начало активности>` |
| `<HH:MM>` | `<обнаружение>` |
| `<HH:MM>` | `<контейнмент>` |
| `<HH:MM>` | `<восстановление>` |

## 4. Затронутые системы и данные

- **Компоненты:** `<агент, tools, MCP, хранилища>`
- **Данные:** `<какие, объём, чувствительность>`
- **Пользователи / клиенты:** `<...>`

## 5. Root cause

- **Первопричина:** `<...>`
- **Способствующие факторы:** `<отсутствующий контроль, пробел в политике>`
- **Какой trust boundary пробит:** `<...>`

## 6. Контейнмент и восстановление

- [ ] Kill-switch / приостановка агента.
- [ ] Отзыв credentials (до/вместе с ротацией): `<какие identity / tokens>`
- [ ] Блокировка egress: `<destinations>`
- [ ] Отзыв / ротация секретов: `<какие>`
- [ ] Блокировка tool / MCP-сервера: `<...>`
- [ ] Очистка poisoned memory / context: `<...>`
- [ ] Восстановление сервиса: `<...>`

### 6.1 Autonomous-agent / containment (если применимо)

Процесс: [§23 Autonomous-agent IR](../notes/part-7-testing-compliance/23-incident-response-recovery.md#playbook-autonomous-agent-ir-containment).

- **Tool-trace artifact** (путь / ID; не user summary): `<...>`
- **User-facing summary vs actual actions:** `<совпадает / расхождения: …>`
- **Pivot check** (hosts / systems contacted): `<...>`
- **Regression eval ID:** `<EVAL-CONTAINMENT-01 / suite / N/A>`
- **Notify:** кого уведомили: `<...>`

## 7. Postmortem (follow-up)

- [ ] Обновить threat model: `<новый риск / контрмера>`
- [ ] Добавить тест / red team кейс: `<...>`
- [ ] Обновить детект / алерт: `<...>`
- [ ] Action items с owner и сроком: `<...>`
- **Дата постмортема:** `<YYYY-MM-DD>`
