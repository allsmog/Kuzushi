import * as fs from "node:fs";
import { beforeEach, describe, expect, it, vi } from "vitest";

// We need to test the parsing logic. Let's mock fs.readFileSync.
vi.mock("node:fs", async () => {
  const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
  return {
    ...actual,
    readFileSync: vi.fn(),
  };
});

import { formatPrecedentsForPrompt, loadPrecedents, type Precedents } from "../src/precedents.js";

const SAMPLE_PRECEDENTS = `## Hard Exclusions
- All SQL queries use parameterized Prisma client
- All routes behind Cognito JWT middleware

## Signal Quality Criteria
- Only flag XSS if raw template output is confirmed
- Ignore CSRF on stateless REST APIs with token auth

## Architectural Precedents
- Auth is handled by AWS Cognito with JWT validation
- mTLS enforced between all k8s services
- React auto-escapes all template output
`;

describe("loadPrecedents", () => {
  const mockReadFileSync = vi.mocked(fs.readFileSync);

  beforeEach(() => {
    mockReadFileSync.mockReset();
  });

  it("parses all three sections from a precedents file", () => {
    mockReadFileSync.mockImplementation((filePath: unknown) => {
      if (String(filePath).includes("precedents.txt")) {
        return SAMPLE_PRECEDENTS;
      }
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    });

    const result = loadPrecedents("/repo");

    expect(result.hardExclusions).toContain("All SQL queries use parameterized Prisma client");
    expect(result.hardExclusions).toContain("All routes behind Cognito JWT middleware");
    expect(result.signalCriteria).toContain("Only flag XSS if raw template output is confirmed");
    expect(result.signalCriteria).toContain("Ignore CSRF on stateless REST APIs with token auth");
    expect(result.architecturalPrecedents).toContain(
      "Auth is handled by AWS Cognito with JWT validation",
    );
    expect(result.architecturalPrecedents).toContain("mTLS enforced between all k8s services");
    expect(result.architecturalPrecedents).toContain("React auto-escapes all template output");
  });

  it("returns empty precedents when file does not exist", () => {
    mockReadFileSync.mockImplementation(() => {
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    });

    const result = loadPrecedents("/repo");

    expect(result.hardExclusions).toEqual([]);
    expect(result.signalCriteria).toEqual([]);
    expect(result.architecturalPrecedents).toEqual([]);
  });

  it("merges global and project precedents", () => {
    mockReadFileSync.mockImplementation((filePath: unknown) => {
      const p = String(filePath);
      if (p.includes(".kuzushi/precedents.txt") && !p.startsWith("/repo")) {
        return "## Hard Exclusions\n- Global exclusion\n";
      }
      if (p.includes("/repo/.kuzushi/precedents.txt")) {
        return "## Hard Exclusions\n- Project exclusion\n";
      }
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    });

    const result = loadPrecedents("/repo");
    expect(result.hardExclusions).toContain("Global exclusion");
    expect(result.hardExclusions).toContain("Project exclusion");
  });

  it("ignores lines that are not list items", () => {
    mockReadFileSync.mockImplementation((filePath: unknown) => {
      const p = String(filePath);
      if (p.includes("/repo/.kuzushi/precedents.txt")) {
        return "## Hard Exclusions\nNot a list item\n- Valid item\n";
      }
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    });

    const result = loadPrecedents("/repo");
    expect(result.hardExclusions).toEqual(["Valid item"]);
  });
});

describe("formatPrecedentsForPrompt", () => {
  it("returns empty array for undefined precedents", () => {
    expect(formatPrecedentsForPrompt(undefined)).toEqual([]);
  });

  it("returns empty array for empty precedents", () => {
    const precedents: Precedents = {
      hardExclusions: [],
      signalCriteria: [],
      architecturalPrecedents: [],
    };
    expect(formatPrecedentsForPrompt(precedents)).toEqual([]);
  });

  it("formats architectural precedents and signal criteria", () => {
    const precedents: Precedents = {
      hardExclusions: ["exclusion1"],
      signalCriteria: ["signal1"],
      architecturalPrecedents: ["arch1", "arch2"],
    };

    const lines = formatPrecedentsForPrompt(precedents);
    expect(lines[0]).toBe("## Organization Security Precedents");
    expect(lines).toContain("- arch1");
    expect(lines).toContain("- arch2");
    expect(lines).toContain("- signal1");
  });
});
