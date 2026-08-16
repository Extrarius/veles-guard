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
- **Ye, Cui, Hadfield-Menell — Prompt Injection as Role Confusion** — <https://arxiv.org/abs/2603.12277> — ICML 2026; роль по стилю, не по тегу; CoT Forgery / inline role claim (§03).
- **Choi et al. — Agent Data Injection Attacks are Realistic Threats to AI Agents** — <https://arxiv.org/abs/2607.05120> — ADI vs instruction injection; isolation trusted vs untrusted data внутри agent context (`Trusted format does not imply trusted data`).
- **Muth & Margraf — From Legacy Documentation to OSCAL: An MCP-Based Agent Pipeline for Threat-Informed Continuous Compliance** — <https://arxiv.org/abs/2607.08288> — MCP-grounded multi-agent pipeline: NL infra docs → knowledge graph → NIST OSCAL SSP/SAR; errors shift to entity extraction (human review).
- **Cyber-Capable AI Agents: Vulnerabilities, Evaluation Containment, and Defensive Response** — <https://arxiv.org/abs/2607.25379> — обзор рисков киберспособных агентов и границ evaluation containment (в т.ч. target / sandbox boundaries).
- **Taught Well Learned Ill: Towards Distillation-conditional Backdoor Attack** — <https://arxiv.org/abs/2509.23871> — закладка в teacher может перейти в student при distillation (§22 model provenance).
- **Stealthy Yet Effective: Distribution-Preserving Backdoor Attacks on Graph Classification** — <https://arxiv.org/abs/2509.26032> — backdoor / triggers на graph classifiers (смежная поверхность; не агентный LLM-runtime).
- **GREAT: Generalizable Backdoor Attacks in RLHF via Emotion-Aware Trigger Synthesis** — <https://arxiv.org/abs/2510.09260> — semantic / emotion-aware triggers в RLHF, не фиксированные токены (§22).
- **Cross-Paradigm Graph Backdoor Attacks with Promptable Subgraph Triggers** — <https://arxiv.org/abs/2510.22555> — promptable subgraph triggers в графовых моделях (смежная поверхность).
- **Enhancing All-to-X Backdoor Attacks with Optimized Target Class Mapping** — <https://arxiv.org/abs/2511.13356> — All-to-X mapping устойчивее простых one-trigger→one-class сценариев (§22).
- **The Trigger in the Haystack** — <https://arxiv.org/abs/2602.03085> — извлечение / реконструкция backdoor-триггеров в LLM без prior knowledge; детекция ≠ гарантия clean weights (§22).
- **AILuminate v1.0** — <https://arxiv.org/abs/2503.05731> — benchmark / taxonomy of harms для оценки safety LLM; ориентир category_hint в guardrail router (§03).
- **Poisoning the Watchtower** — <https://arxiv.org/abs/2605.24421> — adversarial log content → LLM-SOC assistant; paper-опора Security Telemetry Injection (§09).

## Стандарты и фреймворки

- **OWASP Top 10 for Agentic Applications 2026 (ASI Top 10)** — <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/> — ASI01 Agent Goal Hijack, ASI02 Tool Misuse, ASI03 Identity & Privilege Abuse, ASI04 Supply Chain, ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents.
- **OWASP — Agentic AI: Threats and Mitigations** — <https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/>
- **OWASP — Securing Agentic Applications Guide 1.0** — <https://genai.owasp.org/resource/securing-agentic-applications-guide-1-0/>
- **OWASP — Multi-Agentic System Threat Modeling Guide v1.0** — <https://genai.owasp.org/resource/multi-agentic-system-threat-modeling-guide-v1-0/>
- **NIST AI Risk Management Framework (AI RMF 1.0)** — <https://www.nist.gov/itl/ai-risk-management-framework> — рамка управления AI-рисками; класс риска агента R0–R3 / passport — §25.
- **NIST AI Risk Management Framework: Generative AI Profile** — <https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence>
- **NIST SP 800-188 — De-Identifying Government Datasets** — <https://csrc.nist.gov/pubs/sp/800/188/final> — de-identification, quasi-identifiers, governance; канон sanitization / pseudonymization в §04 (mapping не в логах — §15).
- **ENISA — Data Pseudonymisation: Advanced Techniques and Use Cases** — <https://www.enisa.europa.eu/publications/data-pseudonymisation-advanced-techniques-and-use-cases> — псевдонимизация и обратимость; вместе с NIST SP 800-188 для §04 / §15.
- **NIST OSCAL** — <https://pages.nist.gov/OSCAL/> — Open Security Controls Assessment Language; machine-readable SSP/SAR и обмен assessment evidence.
- **MITRE ATLAS** — <https://atlas.mitre.org/>
- **Google SAIF — Secure AI Framework** — <https://safety.google/intl/en_us/safety/saif/>
- **MAESTRO Framework**, **Databricks DASF** — дополнительные фреймворки управления рисками.
- **MLCommons AILuminate** — <https://mlcommons.org/ailuminate/> — taxonomy of harms / safety assessment; см. также arXiv 2503.05731 (§03 guardrail router).

## Практические руководства

- **OpenAI — Safety in building agents** — <https://developers.openai.com/api/docs/guides/agent-builder-safety>
- **OpenAI — Designing AI agents to resist prompt injection** — <https://openai.com/index/designing-agents-to-resist-prompt-injection/>
- **OpenAI — Keeping your data safe when an AI agent clicks a link** — <https://openai.com/index/ai-agent-link-safety/>
- **OpenAI — Guardrails and human review** — <https://developers.openai.com/api/docs/guides/agents/guardrails-approvals>
- **Meta — Llama Guard 3** — <https://www.llama.com/docs/model-cards-and-prompt-formats/llama-guard-3/> — model card / prompt formats для safety classifier (hard policy block на стороне runtime).
- **Zheng et al. — Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena** — <https://arxiv.org/abs/2306.05685> — LLM-as-a-Judge как метод оценки ответов; в RT — доп. слой (не единственный gate; EV-03).
- **OpenAI — GPT-Red: Unlocking Self-Improvement for Robustness** — <https://openai.com/index/unlocking-self-improvement-gpt-red/> — iterative automated red-teaming pattern; канон процесса в §20 Iterative Adversarial Evals.
- **OpenAI — Hugging Face model evaluation security incident** — <https://openai.com/index/hugging-face-model-evaluation-security-incident/> — containment escape / evaluation integrity из eval harness.
- **UK AISI — Incident Report: unsanctioned agent behaviour during cyber testing** — <https://www.aisi.gov.uk/blog/incident-report-unsanctioned-agent-behaviour-during-cyber-testing> — out-of-scope agent trajectory (identity / human contact / artifacts) при permissive cyber eval; опора §20 `EVAL-TRAJECTORY-01` / EV-13.
- **OpenAI — GPT-5.6 Deployment Safety Hub** — <https://deploymentsafety.openai.com/gpt-5-6> — user-facing summary ≠ полный список действий агента; опора IR на tool trace / audit.
- **Google — An Introduction to Google's Approach for Secure AI Agents** — <https://research.google/pubs/an-introduction-to-googles-approach-for-secure-ai-agents/>
- **OWASP — AI Agent Security Cheat Sheet** — Do's & Don'ts (least privilege, валидация входов, human-in-the-loop, изоляция памяти, structured outputs, подпись сообщений, adversarial testing).
- **NVIDIA NeMo Guardrails** — <https://docs.nvidia.com/nemo/guardrails/> — layered input/output/retrieval rails; ориентир guardrail pipeline (§03); [Output Rail Streaming](https://docs.nvidia.com/nemo/guardrails/configure-guardrails/yaml-schema/streaming/output-rail-streaming) — §11 (`chunk_size` / `context_size` / `stream_first`); [Guardrails Configuration](https://docs.nvidia.com/nemo/guardrails/configure-guardrails/yaml-schema/guardrails-configuration) (`rails.retrieval`) + [Fact-Checking](https://docs.nvidia.com/nemo/guardrails/configure-guardrails/guardrail-catalog/fact-checking) — §09 retrieval rails / grounded vs chunks; [Evaluate Guardrails](https://docs.nvidia.com/nemo/guardrails/evaluation/evaluate-guardrails) — §20 EV-10 (per-rail eval, compliance / latency).
- **Microsoft Learn — Generative AI gateway capabilities** — <https://learn.microsoft.com/en-us/azure/api-management/genai-gateway-capabilities> — централизованный контроль доступа, маршрутизация, квоты и observability к LLM; канон AI Gateway / inference proxy в §01, маршрутизация inference в §13, поля лога в §15.

## Threat intelligence (отчёты вендоров)

- **Anthropic — Detecting and countering misuse of AI: August 2025** — <https://www.anthropic.com/news/detecting-countering-misuse-aug-2025> — отчёт Threat Intelligence: злоупотребления agentic AI (в т.ч. автоматизированные атаки через coding agents), меры обнаружения и блокировки.
- **Anthropic — Disrupting the first reported AI-orchestrated cyber espionage campaign (GTG-1002, November 2025)** — <https://www.anthropic.com/news/disrupting-AI-espionage> — первый задокументированный масштабный AI-оркестрированный взлом: автономная разведка, эксплуатация, lateral movement; ~80–90% операций выполнено агентом, человек — в 4–6 точках.
- **Anthropic — Patterns and problems in emerging multiagent systems** — <https://www.anthropic.com/research/multiagent-systems> — Frontier Red Team (13 августа 2026): независимость источников vs majority vote; корреляция моделей (общий контекст / scaffolding); арбитраж вне участников спора (§18, EV-16).
- **Sysdig — JADEPUFFER: Agentic ransomware for automated database extortion** — <https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion> — задокументированный agentic ransomware (ATA): exposed AI/agent framework → credential sweep → pivot → destructive DB extortion; detection signals и рекомендации по защите control plane.
- **Tenet — GhostJacking** — <https://tenetsecurity.ai/blog/ghostjacking-attacks-agentic-kill-chain/> — DEF CON 34: poisoned WAF/SIEM/Sentry/Datadog logs как канал инъекции; read + write в одной сессии; blocked payload остаётся untrusted (§09).

## Prompt Injection

- **Indirect Prompt Injection** (arXiv) — <https://arxiv.org/abs/2302.12173>
- **Design Patterns for Securing LLM Agents against Prompt Injections** — <https://arxiv.org/html/2506.08837v2>
- **Choi et al. — Agent Data Injection (ADI)** — <https://arxiv.org/abs/2607.05120> — untrusted data as trusted metadata / agent context; см. также Академические исследования.
- **Simon Willison — The lethal trifecta for AI agents** — <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/> — private data + untrusted content + external communication; design rule: убрать хотя бы одну «ногу».
- **Legit Security — Remote Prompt Injection in GitLab Duo Leads to Source Code Theft** — <https://www.legitsecurity.com/blog/remote-prompt-injection-in-gitlab-duo> — hidden prompt в MR/контексте → HTML/image URL exfiltration в ответе ассистента.
- **OWASP Prompt Injection Cheat Sheet** — контрольный чек-лист.
- Детекторы: **Lakera Guard**, **Rebuff**, **Prompt Security**, **Meta Prompt Guard**, **LLM Guard Prompt Injection scanner**, **Pangea AI Guard**, **NeMo Guardrails** input/output rails.

## MCP

- **MCP Inspector** — <https://github.com/modelcontextprotocol/inspector>
- **MCP-Scan (Invariant Labs)** — <https://invariantlabs.ai/blog/introducing-mcp-scan>
- **Invariant Labs — GitHub MCP Exploited: Accessing private repositories via MCP** — <https://invariantlabs.ai/blog/mcp-github-vulnerability> — public issue → over-privileged agent → leak private repos via public PR (toxic agent flow / lethal trifecta).
- **Cursor — GHSA-4cxx-hrm3-49rm (CurXecute / CVE-2025-54135)** — <https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm> — prompt injection → write MCP config → RCE via auto-start; NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-54135>.
- **OWASP — Practical Guide for Securely Using Third-Party MCP Servers** — <https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/>
- **OWASP MCP Top 10** — <https://owasp.org/www-project-mcp-top-10/>
- **Snyk Agent Scan** — <https://github.com/snyk/agent-scan>
- **ASSET Research Group — GhostSplice** — <https://asset-group.github.io/disclosures/ghostsplice/> — split-context / compositional MCP injection: `tool.description` + `tool result` + sampling; combined intent; сканер одной поверхности не видит атаку.

## Agent skills / MCP scanning tools

- **OWASP Agentic Skills Top 10** — <https://owasp.org/www-project-agentic-skills-top-10/> — риски agent skills (registry / installation / runtime / governance).
- **MCP-Scan (Invariant Labs)** — <https://invariantlabs.ai/blog/introducing-mcp-scan> — сканер MCP (tool poisoning, rug pull и др.); см. также секцию MCP выше.
- **Snyk Agent Scan** — <https://github.com/snyk/agent-scan> — inventory и scan agent components (MCP servers, skills).
- **promptfoo — LLM red teaming** — <https://www.promptfoo.dev/docs/red-team/> — практики red teaming для LLM / agents.
- **Bumblebee** — <https://github.com/perplexityai/bumblebee> — read-only inventory collector (package / extension / developer-tool metadata); не обязательный workflow.

## Инструменты

- **Guardrails / валидация**: OpenAI Agents SDK Guardrails, LangChain Guardrails, [NVIDIA NeMo Guardrails](https://docs.nvidia.com/nemo/guardrails/), Guardrails AI, LLM Guard.
- **Moderation / classifiers**: OpenAI Moderation API, [Meta Llama Guard 3](https://www.llama.com/docs/model-cards-and-prompt-formats/llama-guard-3/), Lakera Guard, Pangea AI Guard.
- **Sandbox**: Docker hardening, gVisor (<https://gvisor.dev/>), Firecracker, Kata Containers, E2B, Daytona, Anthropic SRT, Microsandbox.
- **DLP / PII**: Microsoft Presidio (<https://github.com/microsoft/presidio>), Protect AI LLM Guard.
- **Red Team / сканеры**: garak (<https://github.com/NVIDIA/garak>), Microsoft PyRIT, promptfoo, DeepTeam, Giskard, Inspect AI.
- **Observability**: Langfuse (<https://langfuse.com/>), LangSmith, OpenTelemetry GenAI semantic conventions (<https://opentelemetry.io/docs/specs/semconv/gen-ai/>).
- **Supply chain / model security**: Protect AI ModelScan (<https://github.com/protectai/modelscan>), NB Defense, Semgrep AI Security Rules, Snyk.

## Книги

- TODO: добавить, если найдутся подходящие издания.
