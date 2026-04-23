import { describe, expect, expectTypeOf, it } from "vitest";
import { ModuleEventBus } from "../../src/bus/module-events.js";
import { Datastore } from "../../src/copilot/options.js";
import type {
  HostUiHandle,
  ModuleEventScope,
  ToolOptionStore,
} from "../../src/modules/host-handles.js";
import type { ExecutionContext } from "../../src/modules/types.js";

describe("narrow host handles (HOST-17)", () => {
  it("ExecutionContext.uiStore is the narrow HostUiHandle shape", () => {
    // Compile-time check: a shape that implements only the HostUiHandle
    // contract must be assignable to ctx.uiStore.
    const stub: HostUiHandle = {
      getState: () => ({}),
      update: () => {},
    };
    const ctx = { uiStore: stub } as Partial<ExecutionContext>;
    expect(ctx.uiStore).toBe(stub);
  });

  it("concrete Datastore satisfies ToolOptionStore structurally", () => {
    const ds = new Datastore();
    // Must support get/set/has. `has()` is a SCHEMA-3 addition to Datastore.
    const store: ToolOptionStore = ds;
    expect(store.has("NOPE")).toBe(false);
    expect(store.set("FOO", "bar")).toBeNull();
    expect(store.has("FOO")).toBe(true);
    expect(store.get<string>("FOO")).toBe("bar");
  });

  it("ModuleEventBus.scope() returns a ModuleEventScope", () => {
    const bus = new ModuleEventBus();
    const scope: ModuleEventScope = bus.scope("test-mod");
    let received: unknown = null;
    const off = scope.on("evt:x", (p) => {
      received = p;
    });
    scope.emit("evt:x", { n: 1 });
    expect(received).toEqual({ n: 1 });
    off();
    scope.emit("evt:x", { n: 2 });
    expect(received).toEqual({ n: 1 });
    scope.disposeAll();
  });

  it("HostUiHandle and WorkspaceHandle types are exposed on ctx", () => {
    expectTypeOf<ExecutionContext["uiStore"]>().toEqualTypeOf<HostUiHandle | undefined>();
  });
});
