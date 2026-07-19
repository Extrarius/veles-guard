---
tags: [ai-security, конспект, литература]
статус: готово
---

# Список литературы

Источники по безопасности AI-агентов, сгруппированные по темам. На эти якоря ссылаются разделы конспекта.

[← Оглавление](../README.md)

## Академические исследования

- **Security of AI Agents** (arXiv, 2024) — формальное описание уязвимостей агентов и методов защиты на уровне компонентов архитектуры.
- **The Emerged Security and Privacy of LLM Agent: A Survey with Case Studies** (ACM Computing Surveys, 2025) — систематизация угроз: унаследованные от LLM и специфичные для агентов (knowledge poisoning, output/functional manipulation).
- **Security Debt in LLM Agent Applications** (ASE 2025, Fudan University) — 221 уязвимость в 50 приложениях, средний CVSS 7.89; 76.5% уязвимостей — из-за LLM2Tool.
- **Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection** — <https://arxiv.org/abs/2302.12173>
- **Design Patterns for Securing LLM Agents against Prompt Injections** — <https://arxiv.org/html/2506.08837v2>

## Стандарты и фреймворки

- **OWASP Top 10 for Agentic Applications 2026 (ASI Top 10)** — <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/> — ASI01 Agent Goal Hijack, ASI02 Tool Misuse, ASI03 Identity & Privilege Abuse, ASI04 Supply Chain, ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents.
- **OWASP — Agentic AI: Threats and Mitigations** — <https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/>
- **OWASP — Securing Agentic Applications Guide 1.0** — <https://genai.owasp.org/resource/securing-agentic-applications-guide-1-0/>
- **OWASP — Multi-Agentic System Threat Modeling Guide v1.0** — <https://genai.owasp.org/resource/multi-agentic-system-threat-modeling-guide-v1-0/>
- **NIST AI Risk Management Framework: Generative AI Profile** — <https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence>
- **MITRE ATLAS** — <https://atlas.mitre.org/>
- **Google SAIF — Secure AI Framework** — <https://safety.google/intl/en_us/safety/saif/>
- **MAESTRO Framework**, **Databricks DASF** — дополнительные фреймворки управления рисками.

## Практические руководства

- **OpenAI — Safety in building agents** — <https://developers.openai.com/api/docs/guides/agent-builder-safety>
- **OpenAI — Designing AI agents to resist prompt injection** — <https://openai.com/index/designing-agents-to-resist-prompt-injection/>
- **OpenAI — Keeping your data safe when an AI agent clicks a link** — <https://openai.com/index/ai-agent-link-safety/>
- **OpenAI — Guardrails and human review** — <https://developers.openai.com/api/docs/guides/agents/guardrails-approvals>
- **OpenAI — GPT-Red: Unlocking Self-Improvement for Robustness** — <https://openai.com/index/unlocking-self-improvement-gpt-red/> — iterative automated red-teaming (attack → observe → mutate → retry), ASR / self-play; дополняет human red team и runtime safeguards.
- **Google — An Introduction to Google's Approach for Secure AI Agents** — <https://research.google/pubs/an-introduction-to-googles-approach-for-secure-ai-agents/>
- **OWASP — AI Agent Security Cheat Sheet** — Do's & Don'ts (least privilege, валидация входов, human-in-the-loop, изоляция памяти, structured outputs, подпись сообщений, adversarial testing).
- **Microsoft — Least privilege for AI agents: Identity, access, and tool binding** — <https://www.microsoft.com/en-us/security/blog/2026/07/16/least-privilege-for-ai-agents-identity-access-and-tool-binding/> — dedicated agent identity, task-scoped RBAC, safe tool binding, JIT elevation, downstream re-auth, end-to-end audit fields, credential revocation.

## Threat intelligence (отчёты вендоров)

- **Anthropic — Detecting and countering misuse of AI: August 2025** — <https://www.anthropic.com/news/detecting-countering-misuse-aug-2025> — отчёт Threat Intelligence: злоупотребления agentic AI (в т.ч. автоматизированные атаки через coding agents), меры обнаружения и блокировки.
- **Anthropic — Disrupting the first reported AI-orchestrated cyber espionage campaign (GTG-1002, November 2025)** — <https://www.anthropic.com/news/disrupting-AI-espionage> — первый задокументированный масштабный AI-оркестрированный взлом: автономная разведка, эксплуатация, lateral movement; ~80–90% операций выполнено агентом, человек — в 4–6 точках.
- **Sysdig — JADEPUFFER: Agentic ransomware for automated database extortion** — <https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion> — задокументированный agentic ransomware (ATA): exposed AI/agent framework → credential sweep → pivot → destructive DB extortion; detection signals и рекомендации по защите control plane.

## Prompt Injection

- **Indirect Prompt Injection** (arXiv) — <https://arxiv.org/abs/2302.12173>
- **Design Patterns for Securing LLM Agents against Prompt Injections** — <https://arxiv.org/html/2506.08837v2>
- **OWASP Prompt Injection Cheat Sheet** — контрольный чек-лист.
- Детекторы: **Lakera Guard**, **Rebuff**, **Prompt Security**, **Meta Prompt Guard**, **LLM Guard Prompt Injection scanner**, **Pangea AI Guard**, **NeMo Guardrails** input/output rails.

## MCP

- **MCP Inspector** — <https://github.com/modelcontextprotocol/inspector>
- **MCP-Scan (Invariant Labs)** — <https://invariantlabs.ai/blog/introducing-mcp-scan>
- **OWASP — Practical Guide for Securely Using Third-Party MCP Servers** — <https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/>
- **OWASP MCP Top 10** — <https://owasp.org/www-project-mcp-top-10/>
- **Snyk Agent Scan** — <https://github.com/snyk/agent-scan>

## Agent skills / MCP scanning tools

- **OWASP Agentic Skills Top 10** — <https://owasp.org/www-project-agentic-skills-top-10/> — риски agent skills (registry / installation / runtime / governance).
- **MCP-Scan (Invariant Labs)** — <https://invariantlabs.ai/blog/introducing-mcp-scan> — сканер MCP (tool poisoning, rug pull и др.); см. также секцию MCP выше.
- **Snyk Agent Scan** — <https://github.com/snyk/agent-scan> — inventory и scan agent components (MCP servers, skills).
- **promptfoo — LLM red teaming** — <https://www.promptfoo.dev/docs/red-team/> — практики red teaming для LLM / agents.
- **Bumblebee** — <https://github.com/perplexityai/bumblebee> — read-only inventory collector (package / extension / developer-tool metadata); не обязательный workflow.

## Инструменты

- **Guardrails / валидация**: OpenAI Agents SDK Guardrails, LangChain Guardrails, NVIDIA NeMo Guardrails, Guardrails AI, LLM Guard.
- **Moderation / classifiers**: OpenAI Moderation API, Meta Llama Guard, Lakera Guard, Pangea AI Guard.
- **Sandbox**: Docker hardening, gVisor (<https://gvisor.dev/>), Firecracker, Kata Containers, E2B, Daytona, Anthropic SRT, Microsandbox.
- **DLP / PII**: Microsoft Presidio (<https://github.com/microsoft/presidio>), Protect AI LLM Guard.
- **Red Team / сканеры**: garak (<https://github.com/NVIDIA/garak>), Microsoft PyRIT, promptfoo, DeepTeam, Giskard, Inspect AI.
- **Observability**: Langfuse (<https://langfuse.com/>), LangSmith, OpenTelemetry GenAI semantic conventions (<https://opentelemetry.io/docs/specs/semconv/gen-ai/>).
- **Supply chain / model security**: Protect AI ModelScan (<https://github.com/protectai/modelscan>), NB Defense, Semgrep AI Security Rules, Snyk.

## Книги

- TODO: добавить, если найдутся подходящие издания.
