import { describe, it, expect, vi } from "vitest";
import * as fs from "node:fs";

vi.mock("node:fs", async () => {
  const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
  return {
    ...actual,
    readFileSync: vi.fn(),
  };
});

import {
  loadSecurityProfiles,
  getProfilesForTask,
  formatProfilesForPrompt,
  type SecurityProfile,
} from "../src/security-profiles.js";

const SAMPLE_PROFILES = `## GDPR Data Protection
- Check for PII logging (names, emails, IPs in log statements)
- Verify data retention limits are enforced
- Ensure right-to-deletion endpoints exist and function

## Financial Transaction Security [appliesTo: code-config-detect, race-condition-detect]
- Double-spend prevention on all monetary operations
- Transaction atomicity with proper DB isolation levels
- Audit trail for all financial state changes

## E-Commerce Specific [appliesTo: *]
- Cart manipulation / price tampering via parameter modification
- Inventory race conditions during checkout
`;

describe("loadSecurityProfiles", () => {
  const mockReadFileSync = vi.mocked(fs.readFileSync);

  it("parses profiles with sections and items", () => {
    mockReadFileSync.mockReturnValue(SAMPLE_PROFILES);

    const profiles = loadSecurityProfiles("/repo");

    expect(profiles).toHaveLength(3);
    expect(profiles[0].name).toBe("GDPR Data Protection");
    expect(profiles[0].items).toHaveLength(3);
    expect(profiles[0].appliesTo).toBeUndefined();

    expect(profiles[1].name).toBe("Financial Transaction Security");
    expect(profiles[1].appliesTo).toEqual(["code-config-detect", "race-condition-detect"]);

    expect(profiles[2].name).toBe("E-Commerce Specific");
    expect(profiles[2].appliesTo).toEqual(["*"]);
  });

  it("returns empty array when file does not exist", () => {
    mockReadFileSync.mockImplementation(() => {
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    });

    expect(loadSecurityProfiles("/repo")).toEqual([]);
  });

  it("skips sections with no items", () => {
    mockReadFileSync.mockReturnValue("## Empty Section\n\n## Has Items\n- item1\n");

    const profiles = loadSecurityProfiles("/repo");
    expect(profiles).toHaveLength(1);
    expect(profiles[0].name).toBe("Has Items");
  });
});

describe("getProfilesForTask", () => {
  const profiles: SecurityProfile[] = [
    { name: "Global", items: ["g1"] },
    { name: "Specific", items: ["s1"], appliesTo: ["code-config-detect"] },
    { name: "Wildcard", items: ["w1"], appliesTo: ["*"] },
    { name: "Other", items: ["o1"], appliesTo: ["secrets-crypto-detect"] },
  ];

  it("returns profiles with no appliesTo (global)", () => {
    const result = getProfilesForTask(profiles, "any-task");
    expect(result.map((p) => p.name)).toContain("Global");
  });

  it("returns profiles matching the task ID", () => {
    const result = getProfilesForTask(profiles, "code-config-detect");
    expect(result.map((p) => p.name)).toContain("Specific");
  });

  it("returns wildcard profiles", () => {
    const result = getProfilesForTask(profiles, "any-task");
    expect(result.map((p) => p.name)).toContain("Wildcard");
  });

  it("excludes non-matching specific profiles", () => {
    const result = getProfilesForTask(profiles, "code-config-detect");
    expect(result.map((p) => p.name)).not.toContain("Other");
  });
});

describe("formatProfilesForPrompt", () => {
  it("returns empty array for no profiles", () => {
    expect(formatProfilesForPrompt([])).toEqual([]);
  });

  it("formats profiles with header and items", () => {
    const profiles: SecurityProfile[] = [
      { name: "GDPR", items: ["Check PII logging", "Verify retention"] },
    ];

    const lines = formatProfilesForPrompt(profiles);
    expect(lines[0]).toBe("## Domain-Specific Security Categories");
    expect(lines).toContain("### GDPR");
    expect(lines).toContain("- Check PII logging");
    expect(lines).toContain("- Verify retention");
  });
});
