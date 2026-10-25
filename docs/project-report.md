# AgentBreaker College Project Report

## Abstract

AgentBreaker is a controlled platform for testing the security behavior of AI agents. The system executes predefined attack scenarios against a deliberately vulnerable local customer-support agent and evaluates more than the final text response. It records tool calls, arguments, data classifications, permissions, action sequence, and evidence. A deterministic analyzer identifies vulnerabilities, assigns a transparent prototype risk score, and presents the result in a dashboard and downloadable assessment report.

## Introduction

AI agents increasingly combine language reasoning with tools that search data, call APIs, and perform actions. A safe-looking response does not prove that the underlying workflow was safe. AgentBreaker demonstrates a practical, educational approach to behavior-centric evaluation inside a bounded synthetic environment.

## Problem Statement

Text-only evaluation can miss unauthorized tool calls, sensitive data access, privilege mismatch, and multi-step action chains. Students and developers need a way to observe and explain these behaviors without attacking real systems or handling real personal information.

## Existing System and Limitations

Simple chat tests typically inspect only the agent's answer. They may not capture which tools were called or whether tool permissions matched the user's request. External red-team platforms can be expensive or difficult to reproduce in a college lab. AgentBreaker addresses this by using local mock tools and a transparent rules engine.

## Proposed System

The proposed system includes a target demo agent, controlled attack catalog, execution engine, behavior logger, deterministic analyzer, risk engine, findings register, and reporting layer. The frontend provides Dashboard, Agents, Attack Lab, Executions, Vulnerabilities, Reports, and Documentation views.

## Objectives and Scope

The objectives are to make behavior observable, detect six core attack categories, generate evidence-backed findings, and keep the demo safe. The scope is limited to a local agent, synthetic customer and invoice fixtures, mock tools, and simulated external communication.

## Requirements

Functional requirements include agent and attack selection, test execution, event trace creation, analyzer output, risk score, history, findings, and report download. Non-functional requirements include input validation, no hardcoded secrets, safe error handling, responsive UX, and reproducible tests.

## Threat Model

The threat model follows: attacker → malicious input → AI agent → tool access → data access → external action → potential impact. Assets include internal synthetic instructions, fixture data, tool permissions, and agent actions. Threats include prompt injection, leakage, tool abuse, exfiltration, privilege escalation, and multi-step attacks. See [`threat-model.md`](threat-model.md).

## Attack Taxonomy

The implemented catalog contains `PI-001`, `PL-001`, `TA-001`, `DE-001`, `PE-001`, `MS-001`, and a `SAFE-001` control. Each definition stores ID, category, name, description, payload, expected behavior, detection conditions, baseline severity, and a technique tag. See [`attack-taxonomy.md`](attack-taxonomy.md).

## System Architecture and Data Flow

```text
React + Tailwind dashboard
       ↓ tRPC
Express server runtime
       ↓
Attack engine → Demo agent → Mock tools → Synthetic fixtures
       ↓
Event logger → Rule analyzer → Risk engine
       ↓
In-memory execution store + Drizzle persistence schema
       ↓
Findings, dashboard, execution details, HTML report
```

## Use Cases

A tester can inspect the demo agent, select Data Exfiltration, run the test, review `read_database()` and `send_email()` activity, inspect sensitive data evidence, follow the attack chain, and download a report. A reviewer can browse historical executions and compare safe baseline behavior with vulnerable scenarios.

## Database Design

The Drizzle schema defines tables for users, agents, attacks, executions, events, and vulnerabilities. The migration was generated and applied to the hosted database. The demo engine uses deterministic seeded records so the control plane is immediately usable; the schema provides a clear path to replacing the in-memory store with relational queries.

## Module Description

- `shared/agentbreaker.ts`: types, tool matrix, attacks, fixtures, risk labels.
- `server/agentbreaker.ts`: simulation, event logger, analyzer, risk engine, reports.
- `server/routers.ts`: validated public procedures used by the frontend.
- `client/src/pages/Home.tsx`: responsive control-plane views.
- `client/src/index.css`: dark operations-console visual system.
- `server/agentbreaker.test.ts`: analyzer regression tests.

## Implementation

The default agent has role `STANDARD`. Customer and invoice reads are allowed, while `DATABASE_READ` and `EXTERNAL_COMMUNICATION` are ADMIN-only. The simulator intentionally demonstrates controlled weaknesses for the vulnerable attack runs. The analyzer compares expected behavior with the observed trace and derives evidence from actual events rather than guessing from prose.

## Testing

The measured test run contains 9 passing tests across 2 test files: 8 analyzer tests and the scaffold logout contract test. The scenarios cover the safe baseline plus all six required attack categories. TypeScript validation and the production build also pass. The Vite build emits a non-blocking bundle-size advisory because the charting and UI libraries are bundled together.

## Results

The seeded demo starts with 6 executions, 5 vulnerable findings, and 1 safe baseline. The dashboard calculates a security score from the current prototype risk model. The data-exfiltration demonstration records a sensitive database access followed by simulated external communication and shows a CRITICAL finding with evidence and recommendations.

## Limitations

This is a controlled educational environment. It uses synthetic data, mock tools, a finite taxonomy, a prototype score, and a deliberately configured target agent. It is not a production security certification, does not guarantee detection of every vulnerability, and does not claim an agent is completely secure. Results depend on the implemented target agent behavior.

## Future Enhancements

Future work could add browser-agent and RAG testing, MCP/tool adapters, multi-agent workflows, automated payload generation, PostgreSQL-backed execution storage, worker queues, CI/CD regression gates, anomaly detection, signed evidence bundles, and organization-level access control.

## Conclusion

AgentBreaker demonstrates why agent security testing must include behavior, not only language output. Its deterministic architecture makes each finding explainable and repeatable while maintaining a strict synthetic-data safety boundary. The project provides a working basis for further research and classroom demonstration.

## References

1. OWASP, *Top 10 for Large Language Model Applications*.
2. MITRE, *ATLAS: Adversarial Threat Landscape for Artificial-Intelligence Systems*.
3. NIST, *AI Risk Management Framework*.
4. Drizzle ORM and tRPC project documentation.
