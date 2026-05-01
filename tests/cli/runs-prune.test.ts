import { describe, expect, it } from "vitest";
import {
  executePrune,
  parseDuration,
  planPrune,
} from "../../src/cli/commands/runs-prune.js";
import type { PipelineRunRecord } from "../../src/store.js";

function mkRun(overrides: Partial<PipelineRunRecord> = {}): PipelineRunRecord {
  return {
    runId: overrides.runId ?? "r-default",
    repo: "/repo/a",
    moduleId: null,
    toolName: null,
    resumeLabel: null,
    startedAt: "2026-01-01T00:00:00Z",
    status: "complete",
    configJson: "{}",
    scanOptsJson: "{}",
    findingsJson: null,
    contextJson: null,
    totalCostUsd: 0,
    completedAt: "2026-01-01T00:01:00Z",
    updatedAt: "2026-01-01T00:01:00Z",
    metricsJson: null,
    assertionsJson: null,
    promptHash: null,
    ...overrides,
  } as PipelineRunRecord;
}

describe("runs-prune", () => {
  describe("parseDuration", () => {
    it("parses seconds, minutes, hours, days, weeks", () => {
      expect(parseDuration("90s")).toBe(90 * 1000);
      expect(parseDuration("30m")).toBe(30 * 60 * 1000);
      expect(parseDuration("12h")).toBe(12 * 3600 * 1000);
      expect(parseDuration("7d")).toBe(7 * 86400 * 1000);
      expect(parseDuration("4w")).toBe(4 * 7 * 86400 * 1000);
    });

    it("is case-insensitive and tolerates whitespace", () => {
      expect(parseDuration(" 7D ")).toBe(7 * 86400 * 1000);
    });

    it("throws on malformed durations", () => {
      expect(() => parseDuration("forever")).toThrow();
      expect(() => parseDuration("7y")).toThrow();
      expect(() => parseDuration("")).toThrow();
    });
  });

  describe("planPrune — older-than", () => {
    const now = Date.parse("2026-04-30T00:00:00Z");

    it("keeps runs newer than the cutoff", () => {
      const runs = [
        mkRun({ runId: "fresh", startedAt: "2026-04-29T00:00:00Z", completedAt: "2026-04-29T00:01:00Z" }),
        mkRun({ runId: "old", startedAt: "2026-01-01T00:00:00Z", completedAt: "2026-01-01T00:01:00Z" }),
      ];
      const out = planPrune(runs, { olderThanMs: 7 * 86400 * 1000, now });
      expect(out.map((r) => r.runId)).toEqual(["old"]);
    });

    it("uses startedAt when completedAt is null (e.g. interrupted runs)", () => {
      const runs = [
        mkRun({
          runId: "stuck",
          startedAt: "2026-01-01T00:00:00Z",
          completedAt: null,
          status: "interrupted",
        }),
      ];
      const out = planPrune(runs, { olderThanMs: 7 * 86400 * 1000, now });
      expect(out.map((r) => r.runId)).toEqual(["stuck"]);
    });

    it("excludes active runs by default", () => {
      const runs = [
        mkRun({
          runId: "running",
          status: "scanning",
          startedAt: "2026-01-01T00:00:00Z",
          completedAt: null,
        }),
      ];
      const def = planPrune(runs, { olderThanMs: 7 * 86400 * 1000, now });
      expect(def).toEqual([]);
      const forced = planPrune(runs, { olderThanMs: 7 * 86400 * 1000, now, includeActive: true });
      expect(forced.map((r) => r.runId)).toEqual(["running"]);
    });
  });

  describe("planPrune — keep-last", () => {
    it("preserves N most recent runs per repo", () => {
      const runs = [
        mkRun({ runId: "a-1", repo: "/a", startedAt: "2026-04-30T00:00:00Z" }),
        mkRun({ runId: "a-2", repo: "/a", startedAt: "2026-04-29T00:00:00Z" }),
        mkRun({ runId: "a-3", repo: "/a", startedAt: "2026-04-28T00:00:00Z" }),
        mkRun({ runId: "b-1", repo: "/b", startedAt: "2026-04-30T00:00:00Z" }),
        mkRun({ runId: "b-2", repo: "/b", startedAt: "2026-04-29T00:00:00Z" }),
      ];
      const out = planPrune(runs, { keepLast: 1 });
      // For each repo, keep the most-recent → drop a-2, a-3, b-2
      expect(new Set(out.map((r) => r.runId))).toEqual(new Set(["a-2", "a-3", "b-2"]));
    });

    it("keep-last=0 drops everything eligible", () => {
      const runs = [mkRun({ runId: "x" }), mkRun({ runId: "y" })];
      expect(planPrune(runs, { keepLast: 0 })).toHaveLength(2);
    });
  });

  describe("executePrune", () => {
    it("dry-run reports candidates without invoking IO", () => {
      const runs = [mkRun({ runId: "old", startedAt: "2020-01-01T00:00:00Z" })];
      const calls: string[] = [];
      const result = executePrune(
        runs,
        { olderThanMs: 86400 * 1000, dryRun: true },
        {
          deleteRow: (id) => {
            calls.push(`row:${id}`);
            return true;
          },
          runDirOf: (r) => `/runs/${r.runId}`,
          rmDir: (d) => calls.push(`rm:${d}`),
        },
      );
      expect(result.candidates).toHaveLength(1);
      expect(result.deletedRows).toBe(0);
      expect(calls).toEqual([]);
    });

    it("non-dry run deletes both DB row + dir", () => {
      const runs = [mkRun({ runId: "old", startedAt: "2020-01-01T00:00:00Z" })];
      const calls: string[] = [];
      const result = executePrune(
        runs,
        { olderThanMs: 86400 * 1000 },
        {
          deleteRow: (id) => {
            calls.push(`row:${id}`);
            return true;
          },
          runDirOf: (r) => `/runs/${r.runId}`,
          rmDir: (d) => calls.push(`rm:${d}`),
        },
      );
      expect(result.deletedRows).toBe(1);
      expect(result.deletedDirs).toBe(1);
      expect(calls).toEqual(["row:old", "rm:/runs/old"]);
    });
  });
});
