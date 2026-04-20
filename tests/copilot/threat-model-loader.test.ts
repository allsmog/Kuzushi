import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ThreatModelDocument } from "../../src/agents/tasks/threat-modeling/types.js";
import {
  formatThreatModelSource,
  loadShellThreatModel,
  loadShellThreatModelForRun,
} from "../../src/copilot/threat-model-loader.js";

const MINIMAL_DOC: ThreatModelDocument = {
  version: "1.0",
  dfd: {
    elements: [
      {
        id: "P1",
        type: "process",
        name: "admin router",
        description: "Express router mounting /admin/*",
        trustZone: "app-vpc",
      },
    ],
    trustBoundaries: [
      {
        id: "B1",
        name: "perimeter",
        innerZone: "app-vpc",
        outerZone: "internet",
        crossingFlows: [],
      },
    ],
  },
  threats: [],
  summary: {
    total: 0,
    bySeverity: {},
    byCategory: {
      spoofing: 0,
      tampering: 0,
      repudiation: 0,
      "information-disclosure": 0,
      "denial-of-service": 0,
      "elevation-of-privilege": 0,
    },
  },
};

describe("threat-model-loader", () => {
  let repoRoot: string;
  beforeEach(() => {
    repoRoot = path.join(tmpdir(), `kuzushi-tml-${Date.now()}`);
    mkdirSync(path.join(repoRoot, ".kuzushi"), { recursive: true });
  });
  afterEach(() => {
    rmSync(repoRoot, { recursive: true, force: true });
  });

  describe("loadShellThreatModel", () => {
    it("returns null when no persistent threat-model.json exists", () => {
      expect(loadShellThreatModel(repoRoot)).toBeNull();
    });

    it("reads .kuzushi/threat-model.json and surfaces path + mtime", () => {
      const p = path.join(repoRoot, ".kuzushi", "threat-model.json");
      writeFileSync(p, JSON.stringify(MINIMAL_DOC));
      const loaded = loadShellThreatModel(repoRoot);
      expect(loaded).not.toBeNull();
      expect(loaded!.document.dfd.elements).toHaveLength(1);
      expect(loaded!.sourcePath).toBe(p);
      expect(loaded!.mtimeMs).toBeGreaterThan(0);
    });

    it("returns null for malformed JSON (doesn't throw)", () => {
      writeFileSync(path.join(repoRoot, ".kuzushi", "threat-model.json"), "{ not json");
      expect(loadShellThreatModel(repoRoot)).toBeNull();
    });
  });

  describe("loadShellThreatModelForRun", () => {
    it("prefers the persistent model over per-run", () => {
      writeFileSync(
        path.join(repoRoot, ".kuzushi", "threat-model.json"),
        JSON.stringify(MINIMAL_DOC),
      );
      const runDir = path.join(repoRoot, ".kuzushi", "runs", "abc123");
      mkdirSync(runDir, { recursive: true });
      writeFileSync(
        path.join(runDir, "threat-model.json"),
        JSON.stringify({ ...MINIMAL_DOC, version: "SHOULD-NOT-WIN" }),
      );
      const loaded = loadShellThreatModelForRun(repoRoot, "abc123");
      expect(loaded).not.toBeNull();
      expect(loaded!.document.version).toBe("1.0");
    });

    it("falls back to per-run when persistent is missing", () => {
      const runDir = path.join(repoRoot, ".kuzushi", "runs", "xyz789");
      mkdirSync(runDir, { recursive: true });
      const perRunPath = path.join(runDir, "threat-model.json");
      writeFileSync(perRunPath, JSON.stringify(MINIMAL_DOC));
      const loaded = loadShellThreatModelForRun(repoRoot, "xyz789");
      expect(loaded).not.toBeNull();
      expect(loaded!.sourcePath).toBe(perRunPath);
    });

    it("returns null when neither file exists", () => {
      expect(loadShellThreatModelForRun(repoRoot, "nope")).toBeNull();
    });
  });

  describe("formatThreatModelSource", () => {
    it("includes 'loaded from' + relative path", () => {
      const home = process.env.HOME ?? "";
      const p = path.join(home, "scratch", "threat-model.json");
      const out = formatThreatModelSource({ sourcePath: p, mtimeMs: Date.now() });
      expect(out).toContain("loaded from");
      expect(out).toContain("~/scratch/threat-model.json");
    });

    it("formats staleness in s / m / h / d", () => {
      const now = Date.now();
      expect(formatThreatModelSource({ sourcePath: "/x", mtimeMs: now - 5000 })).toMatch(
        /\(modified \d+s ago\)/,
      );
      expect(formatThreatModelSource({ sourcePath: "/x", mtimeMs: now - 10 * 60_000 })).toMatch(
        /\(modified \d+m ago\)/,
      );
      expect(formatThreatModelSource({ sourcePath: "/x", mtimeMs: now - 3 * 3_600_000 })).toMatch(
        /\(modified \d+h ago\)/,
      );
      expect(formatThreatModelSource({ sourcePath: "/x", mtimeMs: now - 2 * 86_400_000 })).toMatch(
        /\(modified \d+d ago\)/,
      );
    });
  });
});
