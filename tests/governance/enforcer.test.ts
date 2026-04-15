import { describe, expect, it } from "vitest";
import { GovernanceEnforcer } from "../../src/governance/enforcer.js";
import { defaultScopePolicy } from "../../src/governance/types.js";
import type { ScopePolicy } from "../../src/governance/types.js";

function createEnforcer(overrides: Partial<ScopePolicy> = {}): GovernanceEnforcer {
  return new GovernanceEnforcer({ ...defaultScopePolicy(), ...overrides });
}

describe("GovernanceEnforcer", () => {
  it("allows scan-tier tools by default", () => {
    const enforcer = createEnforcer();
    expect(enforcer.checkExecution("sast:scan", "./repo")).toEqual({ allowed: true });
    expect(enforcer.checkExecution("sast:semgrep")).toEqual({ allowed: true });
  });

  it("blocks tools above maxAutonomousTier when approval required", () => {
    const enforcer = createEnforcer({
      maxAutonomousTier: "scan",
      requireApproval: true,
    });

    expect(enforcer.checkExecution("sast:scan")).toEqual({ allowed: true });

    enforcer.registerToolTier("blackbox:exploit", "exploit");
    const result = enforcer.checkExecution("blackbox:exploit");
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("exploit");
    expect(result.reason).toContain("Approval required");
  });

  it("enforces target scope — allowed targets", () => {
    const enforcer = createEnforcer({
      allowedTargets: ["./acme-api", "./acme-frontend"],
    });

    expect(enforcer.checkExecution("sast:scan", "./acme-api")).toEqual({ allowed: true });

    const denied = enforcer.checkExecution("sast:scan", "./other-repo");
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toContain("not in the allowed scope");
  });

  it("enforces target scope — denied targets take precedence", () => {
    const enforcer = createEnforcer({
      allowedTargets: ["./acme-api"],
      deniedTargets: ["./acme-api/secrets"],
    });

    expect(enforcer.checkExecution("sast:scan", "./acme-api")).toEqual({ allowed: true });

    const denied = enforcer.checkExecution("sast:scan", "./acme-api/secrets");
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toContain("explicitly denied");
  });

  it("enforces budget limits", () => {
    const enforcer = createEnforcer({ budgetUsd: 5.0 });

    expect(enforcer.checkBudget()).toEqual({ allowed: true });

    enforcer.addCost(3.0);
    expect(enforcer.checkBudget()).toEqual({ allowed: true });

    enforcer.addCost(2.5);
    const result = enforcer.checkBudget();
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("Budget exceeded");
  });

  it("builds redacted audit entries", () => {
    const enforcer = createEnforcer();
    const entry = enforcer.buildAuditEntry(
      "sast:scan",
      { target: "./repo", apiKey: "sk-secret" },
      { allowed: true },
      { costUsd: 0.12, workspaceId: "ws-1" },
    );

    expect(entry.action).toBe("sast:scan");
    expect(entry.tier).toBe("scan");
    expect(entry.allowed).toBe(true);
    expect(entry.input.target).toBe("./repo");
    expect(entry.input.apiKey).toBe("[REDACTED]");
    expect(entry.costUsd).toBe(0.12);
    expect(entry.workspaceId).toBe("ws-1");
  });

  it("tracks cumulative cost", () => {
    const enforcer = createEnforcer();
    expect(enforcer.getCumulativeCost()).toBe(0);
    enforcer.addCost(1.5);
    enforcer.addCost(0.75);
    expect(enforcer.getCumulativeCost()).toBe(2.25);
  });

  it("allows all targets when allowedTargets is empty", () => {
    const enforcer = createEnforcer({ allowedTargets: [] });
    expect(enforcer.checkTarget("./any-repo")).toEqual({ allowed: true });
    expect(enforcer.checkTarget("10.0.0.1")).toEqual({ allowed: true });
  });
});
