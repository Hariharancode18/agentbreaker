# AgentBreaker

**AI Agent Security Testing & Vulnerability Analysis Platform**

> **Break the attack. Understand the agent.**

AgentBreaker is a controlled defensive security-testing platform for AI agents. Instead of evaluating only the text returned by an agent, it records the complete behavior trace: the input, response, tool calls, tool arguments, data accessed, permissions used, action sequence, and the resulting policy decision.

This implementation is designed as an understandable college-level full-stack project. It ships with a deliberately vulnerable local demo agent, deterministic rule-based analysis, synthetic fixtures, mock tools, a live-looking dark operations dashboard, execution detail views, and downloadable HTML reports.

## 1. Overview

The project demonstrates how an AI-agent security harness can detect prompt injection, system-prompt leakage, tool abuse, data exfiltration, privilege escalation, and multi-step attack chains. It is intentionally restricted to synthetic local data and mock tools. It does not connect to third-party systems, send real email, or process real credentials.

The hosted implementation uses the Manus WebDev full-stack scaffold: React + TypeScript + Tailwind CSS in the browser, a typed tRPC/Express server, Drizzle schema definitions for future persistence, and a deterministic in-memory execution service for the demo. The runtime adaptation keeps the architecture portable while matching the required behavior.

## 2. Problem Statement

Traditional agent checks often assert that an answer looks safe. That misses failures where the answer appears harmless but the agent accessed a restricted database, used an unauthorized tool, or transmitted data during the generation process. AgentBreaker addresses this observability gap by treating tool and data behavior as first-class security evidence.

## 3. Objectives

1. Run controlled attacks against a local demo agent.
2. Observe and correlate agent responses, tools, arguments, data, permissions, and actions.
3. Detect vulnerabilities with deterministic rules rather than depending only on an LLM.
4. calculate a transparent prototype risk score using Impact × Likelihood × Exposure.
5. Present findings, evidence, attack chains, and recommendations in a usable dashboard.
6. Generate a portable HTML assessment report.

## 4. Features

- Target inventory for the **AgentBreaker Demo Agent**.
- Seven seeded scenarios: six required categories plus an authorized baseline control.
- Tool-permission matrix for `search_customer`, `read_invoice`, `read_database`, and `send_email`.
- Unique execution IDs and ordered event timelines.
- Detection of unauthorized tool calls, sensitive data access, prompt leakage, privilege mismatch, and correlated exfiltration chains.
- Severity, evidence, confidence, recommendation, and risk-score fields.
- Dashboard metrics, severity donut, risk distribution, recent traces, and remediation queue.
- Attack Lab that runs a real server mutation and opens the resulting execution details.
- Vulnerability register, execution table, event trace, behavior-path visualization, and report downloads.
- Drizzle schema and migration for `agentbreaker_agents`, `agentbreaker_attacks`, `agentbreaker_executions`, `agentbreaker_events`, and `agentbreaker_vulnerabilities`.
- No external AI API key required. An optional LLM provider can be added behind the same analyzer interface later.

## 5. Architecture

```text
React dashboard
    ↓ typed tRPC procedures
Express / server runtime
    ↓
Attack engine → controlled payload
    ↓
Demo agent → mock tools → synthetic fixtures
    ↓
Behavior/event logger
    ↓
Deterministic security analyzer
    ↓
Risk engine + vulnerability register
    ↓
Execution details + HTML report
```

The source-of-truth execution logic lives in `server/agentbreaker.ts`. The React control plane is in `client/src/pages/Home.tsx`. Shared domain types, attack definitions, tools, and synthetic fixtures are in `shared/agentbreaker.ts`.

## 6. Technology Stack

| Layer | Technology |
| --- | --- |
| Frontend | React 19, TypeScript, Vite, Tailwind CSS, Recharts, Lucide React, Wouter |
| Backend | Express runtime, tRPC 11, Zod validation |
| Persistence schema | Drizzle ORM, MySQL/TiDB-compatible tables |
| Default agent | Local deterministic mock agent |
| Reports | Downloadable HTML generated server-side |
| Verification | TypeScript compiler, Vitest, WebDev preview, browser screenshots |

The original brief names FastAPI and SQLite. This hosted adaptation uses the platform's supported Node/Express + Drizzle runtime so the project can actually run in the managed environment. The separation between API, engine, analyzer, risk calculation, and data schema remains the same and can be ported to FastAPI/SQLAlchemy later.

## 7. Project Structure

```text
agentbreaker/
├── client/
│   └── src/
│       ├── pages/Home.tsx          # dashboard and all control-plane views
│       ├── App.tsx                 # route shell
│       └── index.css               # dark operations-console design system
├── server/
│   ├── agentbreaker.ts             # attack runner, logger, analyzer, risk, reports
│   ├── routers.ts                  # typed API procedures
│   └── _core/                      # hosted runtime framework
├── shared/agentbreaker.ts          # domain types, attacks, tools, fixtures
├── drizzle/schema.ts               # future relational persistence schema
├── drizzle/0001_clumsy_ego.sql    # applied migration
├── data/                           # synthetic fixture JSON
├── docs/                           # threat model, taxonomy, methodology, report
└── README.md
```

## 8. Installation and Running

This project is already initialized in the hosted WebDev workspace. For a local clone of the same source:

```bash
pnpm install
pnpm dev
```

The development server serves both the Vite frontend and the typed server runtime. Open the preview URL printed by the environment.

## 9. Configuration

No external API key is required. The default mode is always the synthetic demo agent. If you later add a provider, keep credentials server-side and introduce it behind an interface; do not make the deterministic analyzer dependent on an external model.

Synthetic fixtures are clearly marked and use `.synthetic.test` addresses. The mock `send_email` tool writes no real message and performs no network transmission.

## 10. API Procedures

The UI uses typed tRPC procedures rather than handwritten REST wrappers:

| Procedure | Purpose |
| --- | --- |
| `system.health` | Controlled service health check |
| `agents.list`, `agents.create` | Agent inventory and validated registration input |
| `attacks.list`, `attacks.categories` | Attack catalog |
| `tests.run` | Execute an attack against a target agent |
| `executions.list`, `executions.get` | Trace history and detail |
| `vulnerabilities.list`, `vulnerabilities.get` | Findings register |
| `dashboard.overview` | Metrics and chart data |
| `reports.generate`, `reports.list` | HTML assessment generation |

The scaffold also exposes its framework API documentation route where supported by the runtime.

## 11. Attack Categories

- **Prompt Injection** — detects instruction conflict and policy violation.
- **System Prompt Leakage** — detects synthetic internal policy and configuration markers in responses.
- **Tool Abuse** — compares the requested capability with actual tool use.
- **Data Exfiltration** — detects sensitive access followed by simulated external communication.
- **Privilege Escalation** — detects ADMIN-only capability attempted by STANDARD.
- **Multi-Step Attack** — correlates suspicious transitions within one execution ID.
- **Baseline** — benign invoice lookup control used to test false positives.

## 12. Risk Methodology

This project uses its own transparent prototype formula:

```text
Risk = Impact × Likelihood × Exposure
Normalized score = (Risk / 125) × 100
```

Each dimension is scored 1–5. Classification is `SAFE/LOW` for 0–24, `MEDIUM` for 25–49, `HIGH` for 50–74, and `CRITICAL` for 75–100. This is **not an official industry-standard score** and must not be represented as a CVSS replacement.

## 13. Testing

The automated suite covers the required controls:

1. Normal request → safe.
2. Prompt injection → detected.
3. Prompt leakage → detected.
4. Tool abuse → detected.
5. Data exfiltration → detected.
6. Privilege escalation → detected.
7. Multi-step attack → detected.

Run:

```bash
pnpm check
pnpm test
pnpm build
```

The actual measured output is recorded in [`docs/test-results.md`](docs/test-results.md) after execution. Do not infer performance measurements without rerunning the suite.

## 14. Safety Considerations and Limitations

- Controlled environment only; synthetic data only.
- Mock tools do not access customer systems, production databases, or external mail.
- The attack taxonomy is intentionally limited.
- The risk model is a transparent prototype, not a compliance score.
- Results depend on the behavior implemented in the target demo agent.
- LLM-based attacks and explanations are optional future work.
- The platform does not guarantee detection of every AI-agent vulnerability.
- It is not production-grade security certification and must not claim that an agent is “100% secure.”

## 15. Future Enhancements

Potential extensions include automated attack generation, additional RAG/browser/MCP attack categories, multi-agent testing, real-agent adapters, PostgreSQL migration, Redis/Celery workers, anomaly detection, continuous regression testing, CI/CD integration, team management, and signed evidence bundles.

## 16. License

MIT. See [`LICENSE`](LICENSE).
