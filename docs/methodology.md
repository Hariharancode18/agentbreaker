# AgentBreaker Methodology

## Execution

Each run receives a unique execution ID. The engine records attack start, input, tool calls, permission evaluations, data access, agent response, analysis, and vulnerability events. The same ID is used to correlate the entire attack chain.

## Deterministic Analysis

The analyzer compares the attack's expected behavior with the observed behavior. It flags restricted-tool invocation, unauthorized sensitive access, prompt-marker disclosure, ADMIN-only access by STANDARD, sensitive access followed by simulated external communication, and correlated chains.

The implementation intentionally does not require an LLM. This makes the demo reproducible and lets a student reason about each detection rule. An optional model can later improve explanation quality without becoming the source of truth for policy decisions.

## Risk Score

Impact, likelihood, and exposure are each scored from 1 to 5. The raw product is normalized to a 0–100 scale. Severity is derived from the normalized score. The formula is a project-specific prototype and should be recalibrated for a production program.

## Recommendations

Every finding category maps to defensive guidance: trusted/untrusted instruction separation for injection, configuration isolation for leakage, allowlists and argument validation for tool abuse, DLP and approval gates for exfiltration, server-side authorization for privilege escalation, and chain correlation for multi-step attacks.
