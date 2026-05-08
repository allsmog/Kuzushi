/**
 * The auto-triage bridge in shell.ts is simple but important. Instead of
 * booting the whole shell, we replicate its subscription logic directly
 * against a fresh MessageBus + Datastore + JobManager and assert the
 * gating rules hold.
 */

import { describe, expect, it, vi } from "vitest";
import { createBus } from "../../src/bus/adapters/index.js";
import type { MessageBus } from "../../src/bus/types.js";
import { Datastore } from "../../src/copilot/options.js";
import { JobManager } from "../../src/jobs/manager.js";
import type { KuzushiConfig } from "../../src/types.js";

const SEVERITY_ORDER: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function wireAutoTriage(
  bus: MessageBus,
  globals: Datastore,
  jobs: JobManager,
  triage: (fp: string) => Promise<{ output: string }>,
): void {
  type ScanFindingEvent = {
    type: "scan:finding";
    meta: { id: string; timestamp: string; runId: string };
    payload: { finding: { fingerprint: string; severity: string } };
  };
  bus.subscribe<ScanFindingEvent>("scan:finding", (event) => {
    if (String(globals.get("AutoTriage") ?? "").toLowerCase() !== "true") return;
    const minSev = String(globals.get("AUTO_TRIAGE_MIN_SEVERITY") ?? "high").toLowerCase();
    const minRank = SEVERITY_ORDER[minSev] ?? 3;
    const findingSev = String(event.payload.finding.severity ?? "").toLowerCase();
    const findingRank = SEVERITY_ORDER[findingSev] ?? 0;
    if (findingRank < minRank) return;
    const fingerprint = event.payload.finding.fingerprint;
    if (!fingerprint) return;
    jobs.start({ label: `auto-triage:${fingerprint}`, kind: "tool" }, async () => {
      const r = await triage(fingerprint);
      return r.output;
    });
  });
}

function emit(bus: MessageBus, fingerprint: string, severity: string) {
  return bus.publish({
    type: "scan:finding",
    meta: { id: "x", timestamp: new Date().toISOString(), runId: "r" },
    payload: { finding: { fingerprint, severity } },
  } as never);
}

function waitJobs(jobs: JobManager, minCount: number, timeoutMs = 500): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(
      () => reject(new Error(`timeout waiting for ${minCount} jobs; have ${jobs.list().length}`)),
      timeoutMs,
    );
    const tick = () => {
      if (jobs.list().length >= minCount) {
        clearTimeout(t);
        resolve();
        return;
      }
      setImmediate(tick);
    };
    tick();
  });
}

describe("auto-triage bridge", () => {
  const cfg: KuzushiConfig = {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: ["node_modules"],
    taskConfig: { semgrep: {} },
  };

  it("does not trigger when AutoTriage is unset", async () => {
    const bus = createBus(cfg);
    const jobs = new JobManager();
    const triage = vi.fn(async (_fp: string) => ({ output: "ok" }));
    wireAutoTriage(bus, new Datastore(), jobs, triage);
    await emit(bus, "fp_1", "high");
    await new Promise((r) => setImmediate(r));
    expect(jobs.list()).toHaveLength(0);
    expect(triage).not.toHaveBeenCalled();
    await bus.close();
  });

  it("does not trigger when finding severity is below threshold", async () => {
    const bus = createBus(cfg);
    const jobs = new JobManager();
    const globals = new Datastore();
    globals.set("AutoTriage", "true", "global");
    // default threshold is "high"
    const triage = vi.fn(async () => ({ output: "ok" }));
    wireAutoTriage(bus, globals, jobs, triage);
    await emit(bus, "fp_low", "low");
    await emit(bus, "fp_med", "medium");
    await new Promise((r) => setImmediate(r));
    expect(jobs.list()).toHaveLength(0);
    await bus.close();
  });

  it("queues a triage job on high+ severity when AutoTriage is true", async () => {
    const bus = createBus(cfg);
    const jobs = new JobManager();
    const globals = new Datastore();
    globals.set("AutoTriage", "true", "global");
    const triage = vi.fn(async (_fp: string) => ({ output: "triaged" }));
    wireAutoTriage(bus, globals, jobs, triage);
    await emit(bus, "fp_hi", "high");
    await waitJobs(jobs, 1);
    expect(jobs.list()[0]?.label).toBe("auto-triage:fp_hi");
    await bus.close();
  });

  it("respects a lowered AUTO_TRIAGE_MIN_SEVERITY", async () => {
    const bus = createBus(cfg);
    const jobs = new JobManager();
    const globals = new Datastore();
    globals.set("AutoTriage", "true", "global");
    globals.set("AUTO_TRIAGE_MIN_SEVERITY", "medium", "global");
    const triage = vi.fn(async () => ({ output: "ok" }));
    wireAutoTriage(bus, globals, jobs, triage);
    await emit(bus, "fp_med", "medium");
    await waitJobs(jobs, 1);
    expect(jobs.list()[0]?.label).toBe("auto-triage:fp_med");
    await bus.close();
  });

  it("ignores events with no fingerprint", async () => {
    const bus = createBus(cfg);
    const jobs = new JobManager();
    const globals = new Datastore();
    globals.set("AutoTriage", "true", "global");
    const triage = vi.fn(async () => ({ output: "ok" }));
    wireAutoTriage(bus, globals, jobs, triage);
    await emit(bus, "", "critical");
    await new Promise((r) => setImmediate(r));
    expect(jobs.list()).toHaveLength(0);
    await bus.close();
  });
});
