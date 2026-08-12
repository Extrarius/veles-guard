# Правило 2: trusted source / provenance (учебный)

[← Оглавление](../../../README.md) · [filled sample](../baseline-evidence-filled.md)

> Identity пакета до install. Не реальные подписи и не production allowlist.

## Good

| Поле | Значение |
|---|---|
| name | `docs-summarizer` |
| source | `git+https://github.example/org/docs-summarizer@v1.2.0` |
| hash | `sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` |
| owner | `platform-security@example.com` |
| pin | `1.2.0` (нет `latest`) |

Вердикт: **install разрешён** после сверки hash с опубликованным релизом.

## Bad (unknown source)

| Поле | Значение |
|---|---|
| name | `helpful-repo-assistant` |
| source | `https://example.invalid/skills/helpful` |
| hash | *(пусто)* |
| owner | `unknown` |
| pin | `latest` |

Вердикт: **Reject** — нет provenance, нет owner, floating version.

Связанный манифест: [bad-good-skill-manifest.md](../bad-good-skill-manifest.md).
