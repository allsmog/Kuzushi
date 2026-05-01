import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  formatRunReplay,
  formatRunsTable,
  formatRunTrace,
  formatRunTraceJson,
  loadRunSummary,
  readTraceEvents,
} from "../../src/copilot/replay.js";
import {
  RUN_SUMMARY_FILENAME,
  RUN_SUMMARY_SCHEMA_VERSION,
  type RunSummary,
} from "../../src/copilot/run-metadata.js";

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

    it("renders a duration column derived from started/completed", () => {
      const run = makeRun({
        startedAt: "2026-01-01T00:00:00.000Z",
        completedAt: "2026-01-01T00:01:30.000Z",
      });
      const out = formatRunsTable([run]);
      expect(out).toContain("duration");
      expect(out).toContain("1m30s");
    });

    it("filters by status when opts.status is set", () => {
      const runs = [
        makeRun({ runId: "ok", status: "complete" }),
        makeRun({ runId: "stuck", status: "interrupted" }),
      ];
      const out = formatRunsTable(runs, { status: "interrupted" });
      expect(out).toContain("stuck");
      expect(out).not.toContain("ok ");
    });

    it("emits a friendly empty-state message when no runs match the status", () => {
      const runs = [makeRun({ status: "complete" })];
      const out = formatRunsTable(runs, { status: "interrupted" });
      expect(out).toContain('No runs match status="interrupted"');
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

    it("surfaces reproducibility metadata when summary.json is provided", () => {
      const run = makeRun({});
      const summary: RunSummary = {
        schemaVersion: RUN_SUMMARY_SCHEMA_VERSION,
        runId: run.runId,
        status: "complete",
        startedAt: run.startedAt,
        completedAt: run.completedAt!,
        reproducibility: {
          kuzushiVersion: "0.20.0",
          model: "anthropic:claude-opus-4-7",
          agentRuntimeBackend: "claude",
          configHash: "sha256:abc123def456",
          scanArgs: ["scan", "."],
          envFingerprint: { KUZUSHI_DEBUG: "1" },
          git: { sha: "deadbeef1234", branch: "main", dirty: false },
          promptOverrides: [{ module: "core-sast", verb: "triage", sha256: "x" }],
          houseRules: [],
        },
        repo: { root: run.repo },
      };
      const out = formatRunReplay(run, summary);
      expect(out).toContain("reproducibility");
      expect(out).toContain("0.20.0");
      expect(out).toContain("anthropic:claude-opus-4-7");
      expect(out).toContain("deadbee");
      expect(out).toContain("1 override(s)");
    });
  });

  describe("loadRunSummary", () => {
    let dataDir: string;
    beforeEach(() => {
      dataDir = path.join(tmpdir(), `kuzushi-summary-test-${Date.now()}`);
    });
    afterEach(() => {
      rmSync(dataDir, { recursive: true, force: true });
    });

    it("returns undefined when the run dir is missing", () => {
      expect(loadRunSummary(dataDir, "nope")).toBeUndefined();
    });

    it("loads a summary.json from the run dir", () => {
      const runId = "abc";
      const dir = path.join(dataDir, "runs", runId);
      mkdirSync(dir, { recursive: true });
      const summary: RunSummary = {
        schemaVersion: RUN_SUMMARY_SCHEMA_VERSION,
        runId,
        status: "complete",
        startedAt: new Date().toISOString(),
        reproducibility: {
          kuzushiVersion: "0.20.0",
          model: "m",
          configHash: "sha256:x",
          scanArgs: [],
          envFingerprint: {},
          promptOverrides: [],
          houseRules: [],
        },
        repo: { root: "/x" },
      };
      writeFileSync(path.join(dir, RUN_SUMMARY_FILENAME), JSON.stringify(summary));
      expect(loadRunSummary(dataDir, runId)?.runId).toBe(runId);
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

    it("formatRunTraceJson emits one stable-shape JSON per line", () => {
      writeFileSync(
        path.join(runDir, "triage.jsonl"),
        [
          `{"type":"triage:result","timestamp":"2026-01-01T00:00:01Z","fingerprint":"abcd","payload":{"costUsd":0.01}}`,
          `{"type":"triage:result","timestamp":"2026-01-01T00:00:02Z","payload":{}}`,
        ].join("\n"),
      );
      const events = readTraceEvents(dataDir, runId);
      const out = formatRunTraceJson(events);
      const lines = out.split("\n");
      expect(lines).toHaveLength(2);
      for (const line of lines) {
        const parsed = JSON.parse(line);
        // Stable shape: every field present (possibly null) on every line.
        expect(parsed).toHaveProperty("timestamp");
        expect(parsed).toHaveProperty("type");
        expect(parsed).toHaveProperty("source");
        expect(parsed).toHaveProperty("fingerprint");
        expect(parsed).toHaveProperty("payload");
      }
      // Second event has no fingerprint → emitted as null, not undefined.
      const second = JSON.parse(lines[1]!);
      expect(second.fingerprint).toBeNull();
    });

    it("formatRunTraceJson respects the limit", () => {
      const lines = Array.from(
        { length: 5 },
        (_, i) =>
          `{"type":"triage:result","timestamp":"2026-01-01T00:00:0${i}Z","fingerprint":"a${i}","payload":{}}`,
      );
      writeFileSync(path.join(runDir, "triage.jsonl"), lines.join("\n"));
      const events = readTraceEvents(dataDir, runId);
      const out = formatRunTraceJson(events, 2);
      expect(out.split("\n")).toHaveLength(2);
    });
  });
});
