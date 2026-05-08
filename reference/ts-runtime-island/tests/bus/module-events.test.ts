import { describe, expect, it, vi } from "vitest";
import { ModuleEventBus } from "../../src/bus/module-events.js";

describe("ModuleEventBus", () => {
  it("delivers events to every subscribing scope", () => {
    const bus = new ModuleEventBus();
    const a = bus.scope("a");
    const b = bus.scope("b");
    const h1 = vi.fn();
    const h2 = vi.fn();
    a.on("cred:captured", h1);
    b.on("cred:captured", h2);
    bus.emit("cred:captured", { user: "alice" });
    expect(h1).toHaveBeenCalledWith({ user: "alice" });
    expect(h2).toHaveBeenCalledWith({ user: "alice" });
  });

  it("emit() from a scope routes to all scopes on the same bus", () => {
    const bus = new ModuleEventBus();
    const producer = bus.scope("scanner");
    const consumer = bus.scope("watchdog");
    const heard = vi.fn();
    consumer.on("scan:finding", heard);
    producer.emit("scan:finding", { id: "fp_1" });
    expect(heard).toHaveBeenCalledWith({ id: "fp_1" });
  });

  it("on() returns an unsubscribe closure", () => {
    const bus = new ModuleEventBus();
    const s = bus.scope("m");
    const handler = vi.fn();
    const unsub = s.on("x", handler);
    bus.emit("x", 1);
    unsub();
    bus.emit("x", 2);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledWith(1);
  });

  it("once() fires a single time", () => {
    const bus = new ModuleEventBus();
    const s = bus.scope("m");
    const handler = vi.fn();
    s.once("x", handler);
    bus.emit("x", 1);
    bus.emit("x", 2);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("disposeAll() removes every subscription from that scope", () => {
    const bus = new ModuleEventBus();
    const scope = bus.scope("cleanup-me");
    const handler = vi.fn();
    scope.on("a", handler);
    scope.on("b", handler);
    expect(bus.listenerCount("a")).toBe(1);
    expect(bus.listenerCount("b")).toBe(1);
    scope.disposeAll();
    expect(bus.listenerCount("a")).toBe(0);
    expect(bus.listenerCount("b")).toBe(0);
    bus.emit("a");
    bus.emit("b");
    expect(handler).not.toHaveBeenCalled();
  });

  it("disposeAll() on one scope does not touch another scope's subs", () => {
    const bus = new ModuleEventBus();
    const a = bus.scope("a");
    const b = bus.scope("b");
    const ha = vi.fn();
    const hb = vi.fn();
    a.on("e", ha);
    b.on("e", hb);
    a.disposeAll();
    bus.emit("e", "ping");
    expect(ha).not.toHaveBeenCalled();
    expect(hb).toHaveBeenCalledWith("ping");
  });

  it("emit() with no subscribers is a no-op", () => {
    const bus = new ModuleEventBus();
    expect(() => bus.emit("orphan", 123)).not.toThrow();
  });
});
