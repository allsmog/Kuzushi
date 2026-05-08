import { describe, expect, it } from "vitest";
import { createMockBus } from "../../src/testing/index.js";

describe("createMockBus", () => {
  it("records emit calls on .emitted", async () => {
    const bus = createMockBus();
    await (bus as unknown as { emit(t: string, p: unknown): Promise<void> }).emit("foo", { a: 1 });
    await (bus as unknown as { emit(t: string, p: unknown): Promise<void> }).emit("bar", 2);
    expect(bus.emitted).toEqual([
      { eventType: "foo", payload: { a: 1 } },
      { eventType: "bar", payload: 2 },
    ]);
  });

  it("dispatches to subscribers registered via subscribe", async () => {
    const bus = createMockBus();
    const seen: unknown[] = [];
    bus.subscribe("scan:done", (p) => {
      seen.push(p);
    });
    await (bus as unknown as { emit(t: string, p: unknown): Promise<void> }).emit("scan:done", {
      count: 3,
    });
    expect(seen).toEqual([{ count: 3 }]);
  });

  it("awaits async subscribers before resolving emit", async () => {
    const bus = createMockBus();
    const order: string[] = [];
    bus.subscribe("probe", async () => {
      await new Promise((r) => setTimeout(r, 5));
      order.push("handler");
    });
    await (bus as unknown as { emit(t: string, p: unknown): Promise<void> }).emit("probe", null);
    order.push("after-emit");
    expect(order).toEqual(["handler", "after-emit"]);
  });

  it("unsubscribe removes a registered handler", async () => {
    const bus = createMockBus();
    const seen: unknown[] = [];
    const handler = (p: unknown) => {
      seen.push(p);
    };
    bus.subscribe("x", handler);
    bus.unsubscribe("x", handler);
    await (bus as unknown as { emit(t: string, p: unknown): Promise<void> }).emit("x", "payload");
    expect(seen).toEqual([]);
  });

  it("publish({ type, payload }) forwards to emit", async () => {
    const bus = createMockBus();
    await bus.publish({
      type: "event",
      meta: { id: "1", timestamp: "t", runId: "r" },
      payload: "hi",
    });
    expect(bus.emitted).toEqual([{ eventType: "event", payload: "hi" }]);
  });
});
