import { describe, expect, it } from "vitest";
import { CWE_STRATEGY_PROFILES, findProfileForCwe } from "../../src/strategies/cwe-strategy-map.js";

describe("CWE Strategy Map", () => {
  it("has profiles for common CWEs", () => {
    expect(CWE_STRATEGY_PROFILES.length).toBeGreaterThan(0);

    const cwesCovered = CWE_STRATEGY_PROFILES.flatMap((p) => p.cweIds);
    expect(cwesCovered).toContain("CWE-89");
    expect(cwesCovered).toContain("CWE-79");
    expect(cwesCovered).toContain("CWE-918");
    expect(cwesCovered).toContain("CWE-78");
  });

  it("all profiles have at least one strategy", () => {
    for (const profile of CWE_STRATEGY_PROFILES) {
      expect(profile.strategies.length).toBeGreaterThan(0);
    }
  });

  it("strategies within a profile have unique IDs", () => {
    for (const profile of CWE_STRATEGY_PROFILES) {
      const ids = profile.strategies.map((s) => s.strategyId);
      expect(new Set(ids).size).toBe(ids.length);
    }
  });

  it("strategies are ordered by priority", () => {
    for (const profile of CWE_STRATEGY_PROFILES) {
      const priorities = profile.strategies.map((s) => s.priority);
      const sorted = [...priorities].sort((a, b) => a - b);
      expect(priorities).toEqual(sorted);
    }
  });

  describe("findProfileForCwe", () => {
    it("finds profile for SQL injection", () => {
      const profile = findProfileForCwe(["CWE-89"]);
      expect(profile).toBeDefined();
      expect(profile!.vulnClass).toBe("sql-injection");
    });

    it("finds profile for SSRF", () => {
      const profile = findProfileForCwe(["CWE-918"]);
      expect(profile).toBeDefined();
      expect(profile!.vulnClass).toBe("ssrf");
    });

    it("finds profile for auth/authz", () => {
      const profile = findProfileForCwe(["CWE-862"]);
      expect(profile).toBeDefined();
      expect(profile!.vulnClass).toBe("auth-authz");
    });

    it("returns undefined for unknown CWE", () => {
      expect(findProfileForCwe(["CWE-999"])).toBeUndefined();
    });

    it("matches on any CWE in the list", () => {
      const profile = findProfileForCwe(["CWE-999", "CWE-89"]);
      expect(profile).toBeDefined();
    });
  });
});
