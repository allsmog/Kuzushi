import { describe, expect, it, vi } from "vitest";
import { JobManager } from "../../src/jobs/manager.js";

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

describe("JobManager", () => {
  it("starts a job and transitions to completed", async () => {
    const mgr = new JobManager();
    const id = mgr.start({ label: "demo" }, async () => "done");
    expect(id).toBe("1");
    expect(mgr.activeCount()).toBe(1);
    await waitForState(mgr, id, "completed");
    const job = mgr.get(id);
    expect(job?.state).toBe("completed");
    expect(job?.result).toBe("done");
    expect(mgr.activeCount()).toBe(0);
  });

  it("captures errors as failed state", async () => {
    const mgr = new JobManager();
    const id = mgr.start({ label: "boom" }, async () => {
      throw new Error("nope");
    });
    await waitForState(mgr, id, "failed");
    const job = mgr.get(id);
    expect(job?.state).toBe("failed");
    expect(job?.error).toBe("nope");
  });

  it("emits lifecycle events", async () => {
    const mgr = new JobManager();
    const onStarted = vi.fn();
    const onCompleted = vi.fn();
    mgr.on("started", onStarted);
    mgr.on("completed", onCompleted);
    const id = mgr.start({ label: "evt" }, async () => "ok");
    await waitForState(mgr, id, "completed");
    expect(onStarted).toHaveBeenCalledOnce();
    expect(onCompleted).toHaveBeenCalledOnce();
  });

  it("kill() aborts a running job", async () => {
    const mgr = new JobManager();
    const id = mgr.start({ label: "long" }, async ({ signal }) => {
      await new Promise((resolve, reject) => {
        const t = setTimeout(resolve, 10_000);
        signal.addEventListener("abort", () => {
          clearTimeout(t);
          reject(new Error("aborted"));
        });
      });
    });
    expect(mgr.kill(id)).toBe(true);
    await waitForState(mgr, id, "cancelled");
    expect(mgr.get(id)?.state).toBe("cancelled");
    // Double-kill is a no-op.
    expect(mgr.kill(id)).toBe(false);
  });

  it("tail() receives log lines emitted via ctx.log", async () => {
    const mgr = new JobManager();
    const lines: string[] = [];
    // Yield first so mgr.tail() registers before any log() fires.
    const id = mgr.start({ label: "tail" }, async ({ log }) => {
      await new Promise((resolve) => setImmediate(resolve));
      log("hello");
      log("world");
    });
    const unsub = mgr.tail(id, (line) => lines.push(line));
    await waitForState(mgr, id, "completed");
    expect(lines).toEqual(["hello", "world"]);
    unsub();
  });

  it("bounds per-job output to maxOutputLines", async () => {
    const mgr = new JobManager();
    const id = mgr.start({ label: "bounded", maxOutputLines: 3 }, async ({ log }) => {
      for (let i = 0; i < 10; i++) log(`l${i}`);
    });
    await waitForState(mgr, id, "completed");
    expect(mgr.get(id)?.output).toEqual(["l7", "l8", "l9"]);
  });

  it("list() returns newest-first", async () => {
    const mgr = new JobManager();
    const a = mgr.start({ label: "a" }, async () => {});
    await waitForState(mgr, a, "completed");
    await new Promise((r) => setTimeout(r, 5));
    const b = mgr.start({ label: "b" }, async () => {});
    await waitForState(mgr, b, "completed");
    const list = mgr.list();
    expect(list[0]?.id).toBe(b);
    expect(list[1]?.id).toBe(a);
  });

  it("clearCompleted() prunes terminal jobs only", async () => {
    const mgr = new JobManager();
    const done = mgr.start({ label: "d" }, async () => {});
    await waitForState(mgr, done, "completed");
    const running = mgr.start({ label: "r" }, async ({ signal }) => {
      await new Promise((resolve, reject) => {
        signal.addEventListener("abort", () => reject(new Error("aborted")));
      });
    });
    const removed = mgr.clearCompleted();
    expect(removed).toBe(1);
    expect(mgr.get(done)).toBeUndefined();
    expect(mgr.get(running)?.state).toBe("running");
    mgr.kill(running);
    await waitForState(mgr, running, "cancelled");
  });

  it("shutdown() aborts all running jobs", async () => {
    const mgr = new JobManager();
    const id = mgr.start({ label: "s" }, async ({ signal }) => {
      await new Promise((resolve, reject) => {
        signal.addEventListener("abort", () => reject(new Error("aborted")));
      });
    });
    await mgr.shutdown();
    expect(mgr.get(id)?.state).toBe("cancelled");
  });
});
