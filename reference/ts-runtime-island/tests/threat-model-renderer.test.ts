import { describe, expect, it } from "vitest";
import type { ThreatModelDocument } from "../src/agents/tasks/threat-modeling/types.js";
import { renderThreatModelContext } from "../src/threat-model-renderer.js";

function makeBaseDoc(): ThreatModelDocument {
  return {
    version: "1.0",
    dfd: { elements: [], trustBoundaries: [] },
    threats: [],
    summary: { total: 0, bySeverity: {}, byCategory: {} as never },
  };
}

describe("renderThreatModelContext — narrative layer", () => {
  it("renders all five codex-cyber sections when narrative is present", () => {
    const doc: ThreatModelDocument = {
      ...makeBaseDoc(),
      narrative: {
        overview: "Kuzushi is a CLI SAST tool that orchestrates scanners and LLM triage.",
        inputCategories: {
          attackerControlled: ["Repository contents (README.md:1)"],
          operatorControlled: ["CLI flags (src/cli.ts:10)"],
          developerControlled: ["Built-in tasks (src/agents/)"],
          externalServices: ["Anthropic LLM API"],
          sandboxBoundary: ["Docker --network=none for PoCs"],
          assumptions: ["Operator runs on a trusted host"],
        },
        attackerStories: [
          {
            title: "Prompt injection to execute commands",
            narrative:
              "A malicious repo adds README text instructing the LLM to run Bash to exfiltrate secrets.",
            mitigation: "Deny Bash via toolPolicies or run scans in a sandbox.",
            threatIds: ["T-01"],
          },
        ],
        criticalityBuckets: {
          critical: ["RCE on host via prompt injection when shell allows Bash by default"],
          high: ["Leakage of ~/.ssh via symlink traversal"],
          medium: ["DoS via adversarial prompts"],
          low: ["Noisy error messages disclose internal paths"],
        },
        outOfScope: ["Traditional web-app issues (CSRF/XSS/SQLi) — CLI tool has no web UI"],
      },
    };

    const out = renderThreatModelContext(doc);

    // Section 1 — Overview uses narrative text
    expect(out).toContain("### 1. Overview");
    expect(out).toContain("Kuzushi is a CLI SAST tool");

    // Section 2 — Categorised inputs
    expect(out).toContain("### 2. Trust boundaries and assumptions");
    expect(out).toContain("**Attacker-controlled inputs**");
    expect(out).toContain("**Operator-controlled inputs**");
    expect(out).toContain("**Developer-controlled inputs**");
    expect(out).toContain("**External services / dependencies**");
    expect(out).toContain("**Sandbox boundary**");
    expect(out).toContain("**Assumptions**");
    expect(out).toContain("Repository contents (README.md:1)");

    // Section 3 — Attacker stories
    expect(out).toContain("### 3. Attack surface, mitigations and attacker stories");
    expect(out).toContain("**Attacker stories**");
    expect(out).toContain("Prompt injection to execute commands");
    expect(out).toContain("Mitigation: Deny Bash via toolPolicies");
    expect(out).toContain("Related threats: T-01");

    // Section 4 — Criticality buckets with examples
    expect(out).toContain("### 4. Criticality calibration");
    expect(out).toContain("**Critical**");
    expect(out).toContain("RCE on host via prompt injection");
    expect(out).toContain("**High**");
    expect(out).toContain("**Medium**");
    expect(out).toContain("**Low**");

    // Section 5 — Out-of-scope
    expect(out).toContain("### 5. Out-of-scope / less critical classes");
    expect(out).toContain("Traditional web-app issues");
  });

  it("falls back to DFD/STRIDE rendering when no narrative is present (back-compat)", () => {
    const doc: ThreatModelDocument = {
      ...makeBaseDoc(),
      dfd: {
        elements: [
          {
            id: "p1",
            type: "process",
            name: "scan-pipeline",
            description: "Main scan pipeline",
            trustZone: "internal",
          },
        ],
        trustBoundaries: [],
      },
    };

    const out = renderThreatModelContext(doc);

    // Still produces the four section headings
    expect(out).toContain("### 1. Overview");
    expect(out).toContain("### 2. Trust boundaries and assumptions");
    expect(out).toContain("### 3. Attack surface, mitigations and attacker stories");
    expect(out).toContain("### 4. Criticality calibration");
    // No out-of-scope section when narrative is absent
    expect(out).not.toContain("### 5. Out-of-scope");
    // DFD-derived overview content is present
    expect(out).toContain("scan-pipeline");
  });
});
