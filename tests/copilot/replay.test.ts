import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  formatRunReplay,
  formatRunsTable,
  formatRunTrace,
  readTraceEvents,
} from "../../src/copilot/replay.js";

// Minimal mock that matches the subset of PipelineRunRecord the formatters read.
// Using `as any` (via unknown) so we don't need to import the private type.
function makeRun(partial: Record<string, unknown>): Parameters<typeof formatRunReplay>[0] {
  return {
    runId: "7f3a1b2c-0000-0000-0000-000000000000",
    repo: "/path/to/acme-api",
    startedAt: new Date(Date.now() - 120_000).toISOString(),
    status: "complete",
    configJson: "{}",
    scanOptsJson: "{}",
    findingsJson: null,
    contextJson: null,
    totalCostUsd: 0.42,
    completedAt: new Date(Date.now() - 30_000).toISOString(),
    updatedAt: new Date().toISOString(),
    metricsJson: null,
    assertionsJson: null,
    promptHash: null,
    ...partial,
  } as Parameters<typeof formatRunReplay>[0];
}

describe("replay helpers", () => {
  describe("formatRunsTable", () => {
    it("prints empty-state message when no runs exist", () => {
      expect(formatRunsTable([])).toContain("No runs recorded");
    });

    it("renders id / repo / status / cost / findings columns", () => {
      const runs = [makeRun({}), makeRun({ runId: "aabbccdd", status: "scanning", repo: "/b" })];
      const out = formatRunsTable(runs);
      expect(out).toContain("run");
      expect(out).toContain("repo");
      expect(out).toContain("status");
      expect(out).toContain("cost");
      expect(out).toContain("7f3a1b2c");
      expect(out).toContain("aabbccdd");
    });

    it("respects the limit", () => {
      const runs = Array.from({ length: 40 }, (_, i) =>
        makeRun({ runId: `${i.toString().padStart(8, "0")}` }),
      );
      const out = formatRunsTable(runs, 10);
      expect(out).toContain("showing 10 of 40");
    });
  });

  describe("formatRunReplay", () => {
    it("shows severity + verdict buckets from findings_json", () => {
      const findings = [
        {
          verdict: "tp",
          severity: "critical",
          displaySeverity: "critical",
          fingerprint: "a",
          ruleId: "r1",
        },
        {
          verdict: "tp",
          severity: "high",
          displaySeverity: "high",
          fingerprint: "b",
          ruleId: "r2",
        },
        { verdict: "fp", severity: "medium", fingerprint: "c", ruleId: "r3" },
      ];
      const run = makeRun({ findingsJson: JSON.stringify(findings) });
      const out = formatRunReplay(run);
      expect(out).toContain("severity");
      expect(out).toContain("critical");
      expect(out).toContain("verdict");
      expect(out).toContain("tp");
      expect(out).toContain("top true-positives");
    });

    it("handles a run with no findings gracefully", () => {
      const out = formatRunReplay(makeRun({ findingsJson: null }));
      expect(out).toContain("no findings persisted");
    });
  });

  describe("readTraceEvents / formatRunTrace", () => {
    let runDir: string;
    let dataDir: string;
    const runId = "7f3a1b2c";

    beforeEach(() => {
      dataDir = path.join(tmpdir(), `kuzushi-replay-test-${Date.now()}`);
      runDir = path.join(dataDir, "runs", runId);
      mkdirSync(runDir, { recursive: true });
    });
    afterEach(() => {
      rmSync(dataDir, { recursive: true, force: true });
    });

    it("returns empty events when the run dir is missing", () => {
      expect(readTraceEvents(dataDir, "missing-run")).toEqual([]);
    });

    it("parses triage.jsonl + verify.jsonl into sorted events", () => {
      writeFileSync(
        path.join(runDir, "triage.jsonl"),
        [
          `{"type":"triage:result","timestamp":"2026-01-01T00:00:01Z","fingerprint":"abcd","payload":{"costUsd":0.01,"index":1,"total":2,"result":{"verdict":"tp","confidence":0.9}}}`,
          `{"type":"triage:result","timestamp":"2026-01-01T00:00:02Z","fingerprint":"efgh","payload":{"costUsd":0.02,"index":2,"total":2}}`,
          "malformed{",
        ].join("\n"),
      );
      writeFileSync(
        path.join(runDir, "verify.jsonl"),
        `{"type":"verification:result","timestamp":"2026-01-01T00:00:03Z","fingerprint":"abcd","payload":{"costUsd":0.05,"result":{"verdict":"exploitable"}}}\n`,
      );
      const events = readTraceEvents(dataDir, runId);
      expect(events).toHaveLength(3);
      expect(events[0]!.timestamp).toBe("2026-01-01T00:00:01Z");
      expect(events[2]!.type).toBe("verification:result");
    });

    it("formats trace events with columns and a footer", () => {
      const events = readTraceEvents(dataDir, runId);
      const out = formatRunTrace(runId, events);
      expect(out).toContain("No trace events");

      writeFileSync(
        path.join(runDir, "triage.jsonl"),
        `{"type":"triage:result","timestamp":"2026-01-01T00:00:01Z","fingerprint":"abcd","payload":{"costUsd":0.01,"index":1,"total":1,"result":{"verdict":"tp","confidence":0.9},"finding":{"ruleId":"rule/x"}}}\n`,
      );
      const events2 = readTraceEvents(dataDir, runId);
      const out2 = formatRunTrace(runId, events2);
      expect(out2).toContain("triage:result");
      expect(out2).toContain("tp");
      expect(out2).toContain("rule/x");
    });
  });
});
