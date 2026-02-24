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

    await expect(
      bus.waitFor("never:happens", undefined, 20),
    ).rejects.toThrow("Timed out waiting for event");

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
    }>(
      "bus:handler-error",
      (event) => event.meta.runId === "run-err",
    );

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
});
