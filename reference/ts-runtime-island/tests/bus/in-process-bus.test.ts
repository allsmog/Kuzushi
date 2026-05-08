import { describe, expect, it } from "vitest";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";

describe("InProcessBus", () => {
  it("publishes events to subscribers", async () => {
    const bus = new InProcessBus();
    const received: string[] = [];

    const handler = (event: { payload: { value: string } }) => {
      received.push(event.payload.value);
    };

    bus.subscribe("test:event", handler as any);

    await bus.publish({
      type: "test:event",
      meta: { id: "1", timestamp: new Date().toISOString(), runId: "run-1" },
      payload: { value: "hello" },
    });

    expect(received).toEqual(["hello"]);
    await bus.close();
  });

  it("unsubscribe removes handlers", async () => {
    const bus = new InProcessBus();
    let calls = 0;

    const handler = () => {
      calls += 1;
    };

    bus.subscribe("test:event", handler as any);
    bus.unsubscribe("test:event", handler);

    await bus.publish({
      type: "test:event",
      meta: { id: "1", timestamp: new Date().toISOString(), runId: "run-1" },
      payload: {},
    });

    expect(calls).toBe(0);
    await bus.close();
  });

  it("waitFor resolves with matching event", async () => {
    const bus = new InProcessBus();

    const wait = bus.waitFor<{ type: "test:event"; payload: { ok: boolean } }>(
      "test:event",
      (event) => event.payload.ok,
    );

    await bus.publish({
      type: "test:event",
      meta: { id: "1", timestamp: new Date().toISOString(), runId: "run-1" },
      payload: { ok: true },
    });

    const event = await wait;
    expect(event.payload.ok).toBe(true);
    await bus.close();
  });

  it("waitFor rejects on timeout", async () => {
    const bus = new InProcessBus();

    await expect(bus.waitFor("never:happens", undefined, 20)).rejects.toThrow(
      "Timed out waiting for event",
    );

    await bus.close();
  });

  it("emits bus:handler-error when a handler throws", async () => {
    const bus = new InProcessBus();

    bus.subscribe("test:event", () => {
      throw new Error("boom");
    });

    const handlerErrorPromise = bus.waitFor<{
      type: "bus:handler-error";
      payload: {
        sourceEventType: string;
        error: string;
      };
      meta: {
        runId: string;
      };
    }>("bus:handler-error", (event) => event.meta.runId === "run-err");

    await bus.publish({
      type: "test:event",
      meta: { id: "1", timestamp: new Date().toISOString(), runId: "run-err" },
      payload: {},
    });

    const handlerError = await handlerErrorPromise;
    expect(handlerError.payload.sourceEventType).toBe("test:event");
    expect(handlerError.payload.error).toContain("boom");

    await bus.close();
  });

  it("waitFor cleans up the listener when the predicate throws", async () => {
    const bus = new InProcessBus();
    // Pre-access the private emitter via a small side channel: we listen
    // for a different event name and count listeners there to avoid
    // depending on bus internals. Instead, we'll loop waitFor many times
    // and confirm listener count does not grow.
    // node:events exposes listenerCount via `emit` — we'll use the
    // public bus API to probe growth with timeouts.

    for (let i = 0; i < 25; i++) {
      const wait = bus.waitFor<{ type: "test:flaky"; payload: { n: number } }>("test:flaky", () => {
        // Predicate always throws — historically this left the listener registered.
        throw new Error(`boom ${i}`);
      });

      await bus.publish({
        type: "test:flaky",
        meta: { id: String(i), timestamp: new Date().toISOString(), runId: "run-1" },
        payload: { n: i },
      });

      await expect(wait).rejects.toThrow(/boom/);
    }

    // After 25 thrown rejections, the EventEmitter listener count for
    // "test:flaky" should be 0 — no leaked listeners.
    // Access the underlying emitter via a test-only probe on the bus.
    const emitter = (bus as unknown as { emitter: { listenerCount: (name: string) => number } })
      .emitter;
    expect(emitter.listenerCount("test:flaky")).toBe(0);

    await bus.close();
  });

  it("waitFor cleans up the listener when waitFor times out", async () => {
    const bus = new InProcessBus();

    const promise = bus.waitFor("never:ever:happens", undefined, 15);
    await expect(promise).rejects.toThrow("Timed out");

    const emitter = (bus as unknown as { emitter: { listenerCount: (name: string) => number } })
      .emitter;
    expect(emitter.listenerCount("never:ever:happens")).toBe(0);

    await bus.close();
  });
});
