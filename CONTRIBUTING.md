# Contributing / Участие в проекте

## Русский

Спасибо за интерес к **AI Agent Security Handbook**. Внешние правки приветствуются через issues и pull requests, но все изменения проходят **ручное ревью** maintainer.

### Как предложить изменение

1. Открой issue (шаблон «Исправление» или «Предложение») или сразу PR от форка.
2. Укажи раздел конспекта (`notes/part-*/NN-*.md`) или общий файл.
3. Для фактов и угроз — **первоисточники** (официальные docs, стандарты, отчёты вендоров, papers). Без Habr/блогов как единственной ссылки.
4. Примеры кода — **безопасные и sandbox-friendly**; без реальных секретов, токенов, URL внутренних систем.

### Что мы принимаем

- исправления фактов, опечаток, формулировок;
- уточнения threat context, контрмер, чек-листов;
- новые разделы или расширения — по согласованию с maintainer.

### Что мы не принимаем

- **offensive payload dumps** и готовые эксплойты против чужих систем;
- инструкции по атаке на чужую инфраструктуру без образовательного и defensive контекста;
- материалы без источников или с сомнительной операционной применимостью;
- PR, нарушающие [SECURITY.md](SECURITY.md).

Maintainer оставляет за собой право **не принимать** спорные, небезопасные или слабо обоснованные материалы — особенно в темах MCP, supply chain, red teaming и AI-coding.

### Pull requests

- один PR — одна логическая тема;
- заполни шаблон PR (риск, проверки, раздел);
- ожидай review от code owner.

---

## English

Thank you for your interest in **AI Agent Security Handbook**. External contributions are welcome via issues and pull requests, but all changes are **manually reviewed** by the maintainer.

### How to propose a change

1. Open an issue (Correction or Suggestion template) or submit a PR from a fork.
2. Reference the handbook section (`notes/part-*/NN-*.md`) or shared file you are changing.
3. For facts and threats, cite **primary sources** (official docs, standards, vendor reports, papers). Do not use blog posts as the only reference.
4. Code examples must be **safe and sandbox-friendly**; no real secrets, tokens, or internal system URLs.

### What we accept

- factual corrections, typos, clearer wording;
- threat context, controls, and checklist improvements;
- new sections or expansions — in coordination with the maintainer.

### What we do not accept

- **offensive payload dumps** and ready-to-use exploits against third-party systems;
- instructions for attacking someone else's infrastructure without clear educational and defensive framing;
- unsourced material or content with questionable operational misuse potential;
- PRs that violate [SECURITY.md](SECURITY.md).

The maintainer may **decline** controversial, unsafe, or poorly sourced changes — especially in MCP, supply chain, red teaming, and AI-coding topics.

### Pull requests

- one PR per logical topic;
- fill in the PR template (risk, checks, section);
- expect review from the code owner.
