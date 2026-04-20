/**
 * AutoVerify / AutoPatch bridges in shell.ts. Tests replicate the subscription
 * logic against a fresh MessageBus + Datastore + JobManager so we don't have
 * to stand up the full shell.
 */

import { describe, expect, it, vi } from "vitest";
import { createBus } from "../../src/bus/adapters/index.js";
import type { MessageBus } from "../../src/bus/types.js";
import { Datastore } from "../../src/copilot/options.js";
import { JobManager } from "../../src/jobs/manager.js";
import type { KuzushiConfig } from "../../src/types.js";

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

function wireAutoVerify(
  bus: MessageBus,
  globals: Datastore,
  jobs: JobManager,
  verify: (fp: string) => Promise<{ output: string }>,
): void {
  type TriageResultEvent = {
    type: "triage:result";
    meta: { id: string; timestamp: string; runId: string };
    payload: { finding: { fingerprint: string }; result: { verdict: string } };
  };
  bus.subscribe<TriageResultEvent>("triage:result", (event) => {
    if (String(globals.get("AutoVerify") ?? "").toLowerCase() !== "true") return;
    if (event.payload.result.verdict !== "tp") return;
    const fingerprint = event.payload.finding.fingerprint;
    if (!fingerprint) return;
    jobs.start(
      { label: `auto-verify:${fingerprint}` },
      async () => (await verify(fingerprint)).output,
    );
  });
}

function wireAutoPatch(
  bus: MessageBus,
  globals: Datastore,
  jobs: JobManager,
  patch: (fp: string) => Promise<{ output: string }>,
): void {
  type VerificationResultEvent = {
    type: "verification:result";
    meta: { id: string; timestamp: string; runId: string };
    payload: { finding: { fingerprint: string }; result: { exploitable: boolean } };
  };
  bus.subscribe<VerificationResultEvent>("verification:result", (event) => {
    if (String(globals.get("AutoPatch") ?? "").toLowerCase() !== "true") return;
    if (!event.payload.result.exploitable) return;
    const fingerprint = event.payload.finding.fingerprint;
    if (!fingerprint) return;
    jobs.start(
      { label: `auto-patch:${fingerprint}` },
      async () => (await patch(fingerprint)).output,
    );
  });
}

function emitTriage(bus: MessageBus, fingerprint: string, verdict: string) {
  return bus.publish({
    type: "triage:result",
    meta: { id: "x", timestamp: new Date().toISOString(), runId: "r" },
    payload: { finding: { fingerprint }, result: { verdict } },
  } as never);
}

function emitVerify(bus: MessageBus, fingerprint: string, exploitable: boolean) {
  return bus.publish({
    type: "verification:result",
    meta: { id: "x", timestamp: new Date().toISOString(), runId: "r" },
    payload: { finding: { fingerprint }, result: { exploitable } },
  } as never);
}

function waitJobs(jobs: JobManager, minCount: number, timeoutMs = 500): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(
      () => reject(new Error(`timeout waiting for ${minCount} jobs`)),
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

describe("auto-verify bridge", () => {
  it("does not trigger when AutoVerify is unset", async () => {
    const bus = createBus(cfg);
    const jobs = new JobManager();
    const verify = vi.fn(async () => ({ output: "ok" }));
    wireAutoVerify(bus, new Datastore(), jobs, verify);
    await emitTriage(bus, "fp_1", "tp");
    await new Promise((r) => setImmediate(r));
    expect(jobs.list()).toHaveLength(0);
    expect(verify).not.toHaveBeenCalled();
    await bus.close();
  });

  it("ignores non-tp verdicts", async () => {
    const bus = createBus(cfg);
    const jobs = new JobManager();
    const globals = new Datastore();
    globals.set("AutoVerify", "true", "global");
    const verify = vi.fn(async () => ({ output: "ok" }));
    wireAutoVerify(bus, globals, jobs, verify);
    await emitTriage(bus, "fp_fp", "fp");
    await emitTriage(bus, "fp_nr", "needs_review");
    await new Promise((r) => setImmediate(r));
    expect(jobs.list()).toHaveLength(0);
    await bus.close();
  });

  it("queues verify:finding on tp verdict when AutoVerify is true", async () => {
    const bus = createBus(cfg);
    const jobs = new JobManager();
    const globals = new Datastore();
    globals.set("AutoVerify", "true", "global");
    const verify = vi.fn(async () => ({ output: "verified" }));
    wireAutoVerify(bus, globals, jobs, verify);
    await emitTriage(bus, "fp_tp", "tp");
    await waitJobs(jobs, 1);
    expect(jobs.list()[0]?.label).toBe("auto-verify:fp_tp");
    await bus.close();
  });
});

describe("auto-patch bridge", () => {
  it("does not trigger when AutoPatch is unset", async () => {
    const bus = createBus(cfg);
    const jobs = new JobManager();
    const patch = vi.fn(async () => ({ output: "ok" }));
    wireAutoPatch(bus, new Datastore(), jobs, patch);
    await emitVerify(bus, "fp_1", true);
    await new Promise((r) => setImmediate(r));
    expect(jobs.list()).toHaveLength(0);
    expect(patch).not.toHaveBeenCalled();
    await bus.close();
  });

  it("ignores non-exploitable verification results", async () => {
    const bus = createBus(cfg);
    const jobs = new JobManager();
    const globals = new Datastore();
    globals.set("AutoPatch", "true", "global");
    const patch = vi.fn(async () => ({ output: "ok" }));
    wireAutoPatch(bus, globals, jobs, patch);
    await emitVerify(bus, "fp_safe", false);
    await new Promise((r) => setImmediate(r));
    expect(jobs.list()).toHaveLength(0);
    await bus.close();
  });

  it("queues patch:finding on exploitable + AutoPatch=true", async () => {
    const bus = createBus(cfg);
    const jobs = new JobManager();
    const globals = new Datastore();
    globals.set("AutoPatch", "true", "global");
    const patch = vi.fn(async () => ({ output: "patched" }));
    wireAutoPatch(bus, globals, jobs, patch);
    await emitVerify(bus, "fp_bad", true);
    await waitJobs(jobs, 1);
    expect(jobs.list()[0]?.label).toBe("auto-patch:fp_bad");
    await bus.close();
  });
});
