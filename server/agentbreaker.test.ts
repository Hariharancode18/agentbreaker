import { describe, expect, it } from "vitest";
import { createAgent, getAgent, getExecution, listAgents, listAttacks, runAttack } from "./agentbreaker";

describe("AgentBreaker deterministic security analyzer", () => {
  it("keeps the baseline invoice request safe", () => {
    const attack = listAttacks().find(item => item.id === "SAFE-001")!;
    const execution = runAttack("agent-demo-001", attack.id);
    expect(execution.analysis.result).toBe("SAFE");
    expect(execution.analysis.riskScore).toBe(0);
    expect(execution.toolCalls.map(call => call.tool)).toEqual(["read_invoice"]);
  });

  it.each([
    ["PI-001", "Prompt Injection"],
    ["PL-001", "System Prompt Leakage"],
    ["TA-001", "Tool Abuse"],
    ["DE-001", "Data Exfiltration"],
    ["PE-001", "Privilege Escalation"],
    ["MS-001", "Multi-Step Attack"],
  ])("detects %s as %s", (attackId, category) => {
    const execution = runAttack("agent-demo-001", attackId);
    expect(execution.analysis.result).toBe("VULNERABLE");
    expect(execution.analysis.category).toBe(category);
    expect(execution.analysis.riskScore).toBeGreaterThan(0);
    expect(execution.events.length).toBeGreaterThan(3);
    expect(getExecution(execution.id)?.id).toBe(execution.id);
  });

  it("records the exfiltration chain as one correlated execution", () => {
    const execution = runAttack("agent-demo-001", "DE-001");
    expect(execution.events.every(event => event.executionId === execution.id)).toBe(true);
    expect(execution.toolCalls.map(call => call.tool)).toEqual(["read_database", "send_email"]);
    expect(execution.dataAccessed).toContain("customers:* (SENSITIVE)");
    expect(execution.analysis.evidence.some(item => item.includes("external communication"))).toBe(true);
  });

  it("keeps the Demo Agent registered with its deliberate four-tool profile", () => {
    const demo = getAgent("agent-demo-001");
    expect(demo?.name).toBe("AgentBreaker Demo Agent");
    expect(demo?.agentType).toBe("MOCK");
    expect(demo?.tools.map(tool => tool.name)).toEqual(["search_customer", "read_invoice", "read_database", "send_email"]);
  });

  it("registers a valid mock agent and returns it from the live registry", () => {
    const agent = createAgent({ name: "Customer Support Agent", description: "Controlled customer support agent for local testing.", agentType: "MOCK", model: "AgentBreaker Mock Agent", role: "STANDARD", toolNames: ["search_customer", "read_invoice"] });
    expect(listAgents().some(item => item.id === agent.id)).toBe(true);
    expect(getAgent(agent.id)?.tools.map(tool => tool.name)).toEqual(["search_customer", "read_invoice"]);
  });

  it("rejects tools that are incompatible with the selected role", () => {
    expect(() => createAgent({ name: "Invalid Tool Agent", description: "This configuration should be rejected.", agentType: "MOCK", model: "AgentBreaker Mock Agent", role: "STANDARD", toolNames: ["read_database"] })).toThrow(/incompatible/);
  });

  it("passes the selected registered agent into execution metadata", () => {
    const agent = createAgent({ name: "Metadata Test Agent", description: "Controlled agent for metadata verification.", agentType: "MOCK", model: "AgentBreaker Mock Agent", role: "STANDARD", toolNames: ["search_customer", "read_invoice"] });
    const execution = runAttack(agent.id, "SAFE-001");
    expect(execution.agentId).toBe(agent.id);
    expect(execution.agentName).toBe(agent.name);
    expect(execution.attackCategory).toBe("Baseline");
    expect(getExecution(execution.id)?.agentId).toBe(agent.id);
  });
});
