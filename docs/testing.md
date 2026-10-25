# Testing Methodology

AgentBreaker uses a deterministic test suite so every result can be reproduced without an external API key. The safe baseline validates that the analyzer does not treat every tool call as malicious. Each required attack category then checks result type, category, non-zero risk, event count, and execution lookup. The exfiltration test additionally checks that all events share one execution ID, that the sensitive data marker is retained, and that evidence includes the external-communication transition.

The project also runs TypeScript validation and a production build. Browser preview verification confirms the dashboard, Attack Lab, and execution pages render with real procedure data. The test results document records the measured runner output and explicitly limits interpretation to the finite implemented scenario set.
