/**
 * End-to-end-ish test for the JobManager → desktop-notify bridge.
 *
 * We mock `sendCompletionNotification` so no real toast fires, then inline
 * the exact opt-in logic `shell.ts` uses and assert it:
 *   - skips when NOTIFY_ON_COMPLETE is unset / falsy
 *   - skips when the job ran shorter than NOTIFY_THRESHOLD_SECS
 *   - fires on completed/failed/cancelled when opted-in AND over threshold
 */

import { describe, expect, it, vi } from "vitest";
import { Datastore } from "../../src/copilot/options.js";
import { JobManager } from "../../src/jobs/manager.js";
import { sendCompletionNotification } from "../../src/ui/notify.js";

vi.mock("../../src/ui/notify.js", () => ({
  sendCompletionNotification: vi.fn(),
}));

function wireBridge(jobManager: JobManager, globals: Datastore): void {
  const notifyIfOptedIn = (label: string, verb: string, record: { startedAt: number }) => {
    if (String(globals.get("NOTIFY_ON_COMPLETE") ?? "").toLowerCase() !== "true") return;
    const thresholdRaw = String(globals.get("NOTIFY_THRESHOLD_SECS") ?? "30");
    const threshold = Number.parseInt(thresholdRaw, 10);
    const elapsedSecs = (Date.now() - record.startedAt) / 1000;
    if (!Number.isFinite(threshold) || elapsedSecs < threshold) return;
    sendCompletionNotification(`Kuzushi: job ${verb}`, `${label} (${elapsedSecs.toFixed(0)}s)`);
  };
  jobManager.on("completed", (job) => notifyIfOptedIn(job.label, "completed", job));
  jobManager.on("failed", (job) => notifyIfOptedIn(job.label, "failed", job));
  jobManager.on("cancelled", (job) => notifyIfOptedIn(job.label, "cancelled", job));
}

function waitForState(mgr: JobManager, id: string, target: string, timeoutMs = 500) {
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`timeout waiting for ${id} to reach ${target}`)),
      timeoutMs,
    );
    const tick = () => {
      const job = mgr.get(id);
      if (job && job.state === target) {
        clearTimeout(timer);
        resolve();
        return;
      }
      setImmediate(tick);
    };
    tick();
  });
}

describe("JobManager → sendCompletionNotification bridge", () => {
  it("stays silent when NOTIFY_ON_COMPLETE is unset", async () => {
    const mgr = new JobManager();
    const globals = new Datastore();
    wireBridge(mgr, globals);
    const id = mgr.start({ label: "short" }, async () => "done");
    await waitForState(mgr, id, "completed");
    expect(sendCompletionNotification).not.toHaveBeenCalled();
  });

  it("stays silent below the duration threshold", async () => {
    const mgr = new JobManager();
    const globals = new Datastore();
    globals.set("NOTIFY_ON_COMPLETE", "true", "global");
    globals.set("NOTIFY_THRESHOLD_SECS", "999", "global");
    wireBridge(mgr, globals);
    const id = mgr.start({ label: "too-short" }, async () => {});
    await waitForState(mgr, id, "completed");
    expect(sendCompletionNotification).not.toHaveBeenCalled();
  });

  it("fires when opted-in and over the threshold (threshold=0 exercises both gates)", async () => {
    const mgr = new JobManager();
    const globals = new Datastore();
    globals.set("NOTIFY_ON_COMPLETE", "true", "global");
    globals.set("NOTIFY_THRESHOLD_SECS", "0", "global");
    wireBridge(mgr, globals);
    const id = mgr.start({ label: "long-scan" }, async () => "done");
    await waitForState(mgr, id, "completed");
    expect(sendCompletionNotification).toHaveBeenCalledWith(
      "Kuzushi: job completed",
      expect.stringContaining("long-scan"),
    );
  });

  it("fires distinct titles on failed / cancelled transitions", async () => {
    const mgr = new JobManager();
    const globals = new Datastore();
    globals.set("NOTIFY_ON_COMPLETE", "true", "global");
    globals.set("NOTIFY_THRESHOLD_SECS", "0", "global");
    wireBridge(mgr, globals);
    (sendCompletionNotification as unknown as { mockClear: () => void }).mockClear();

    const failId = mgr.start({ label: "boom" }, async () => {
      throw new Error("nope");
    });
    await waitForState(mgr, failId, "failed");
    expect(sendCompletionNotification).toHaveBeenCalledWith(
      "Kuzushi: job failed",
      expect.stringContaining("boom"),
    );

    const cancelId = mgr.start({ label: "canceled" }, async ({ signal }) => {
      await new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(new Error("aborted")));
      });
    });
    mgr.kill(cancelId);
    await waitForState(mgr, cancelId, "cancelled");
    expect(sendCompletionNotification).toHaveBeenCalledWith(
      "Kuzushi: job cancelled",
      expect.stringContaining("canceled"),
    );
  });
});
