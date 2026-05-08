import { describe, expect, it } from "vitest";
import {
  createMockEventScope,
  createMockOptionStore,
  createMockToolContext,
  createMockUiStore,
  createMockWorkspace,
  createRecordingLogger,
  createRecordingPrintSink,
  getRecordedActivity,
  getRecordedOutput,
  noopRuntime,
} from "../../src/testing/index.js";

describe("createMockToolContext", () => {
  it("supplies defaults for every documented ExecutionContext field", () => {
    const ctx = createMockToolContext();
    expect(ctx.cwd).toBeTypeOf("string");
    expect(ctx.runtime).toBe(noopRuntime);
    expect(ctx.bus).toBeTruthy();
    expect(ctx.config).toBeTruthy();
    expect(ctx.host?.sdkVersion).toBe("0.0.0-test");
    expect(ctx.host?.capabilities.has("workspace")).toBe(true);
    expect(ctx.logger).toBeTruthy();
    expect(ctx.uiStore).toBeTruthy();
    expect(ctx.datastore).toBeTruthy();
    expect(ctx.workspace).toBeTruthy();
    expect(ctx.events).toBeTruthy();
    expect(ctx.print).toBeTruthy();
    expect(ctx.seedTaskOutputs).toBeInstanceOf(Map);
    expect(typeof ctx.reportActivity).toBe("function");
    expect(typeof ctx.reportOutput).toBe("function");
  });

  it("applies config overrides on top of the defaults", () => {
    const ctx = createMockToolContext({
      config: { model: "anthropic:haiku" },
    });
    expect(ctx.config.model).toBe("anthropic:haiku");
    // Untouched defaults should survive.
    expect(ctx.config.triageBatchSize).toBe(5);
  });

  it("lets the caller override individual mock stubs", () => {
    const logger = createRecordingLogger();
    const workspace = createMockWorkspace();
    const datastore = createMockOptionStore({ TRIAGE_MODEL: "haiku" });
    const uiStore = createMockUiStore({ phase: "idle" });
    const events = createMockEventScope();
    const print = createRecordingPrintSink();
    const ctx = createMockToolContext({
      logger,
      workspace,
      datastore,
      uiStore,
      events,
      print,
    });
    expect(ctx.logger).toBe(logger);
    expect(ctx.workspace).toBe(workspace);
    expect(ctx.datastore).toBe(datastore);
    expect(ctx.uiStore).toBe(uiStore);
    expect(ctx.events).toBe(events);
    expect(ctx.print).toBe(print);
    expect(ctx.datastore?.get("triage_model")).toBe("haiku");
  });

  it("overrides host.sdkVersion + capabilities when provided", () => {
    const ctx = createMockToolContext({
      host: { sdkVersion: "9.9.9", capabilities: ["workspace"] },
    });
    expect(ctx.host?.sdkVersion).toBe("9.9.9");
    expect(ctx.host?.capabilities.has("workspace")).toBe(true);
    expect(ctx.host?.capabilities.has("ui-store")).toBe(false);
  });

  it("records reportActivity + reportOutput calls via the helper accessors", () => {
    const ctx = createMockToolContext();
    ctx.reportActivity?.("scanning deps");
    ctx.reportActivity?.("analyzing lodash@4", { step: 1, total: 3 });
    ctx.reportOutput?.("npm install: ok");
    expect(getRecordedActivity(ctx)).toEqual([
      { description: "scanning deps" },
      { description: "analyzing lodash@4", meta: { step: 1, total: 3 } },
    ]);
    expect(getRecordedOutput(ctx)).toEqual(["npm install: ok"]);
  });

  it("accepts a custom reportActivity spy which replaces the default", () => {
    const spy: Array<string> = [];
    const ctx = createMockToolContext({
      reportActivity: (d) => {
        spy.push(d);
      },
    });
    ctx.reportActivity?.("custom");
    expect(spy).toEqual(["custom"]);
    // Default recorder disabled when overridden.
    expect(getRecordedActivity(ctx)).toEqual([]);
  });

  it("preserves backward compat: zero-arg call returns a usable context", async () => {
    const ctx = createMockToolContext();
    // Should be usable as the ExecutionContext that pre-existing tools
    // already consume (cwd, runtime, bus, config).
    expect(ctx.cwd).toBeTruthy();
    expect(ctx.runtime).toBeTruthy();
    expect(ctx.bus).toBeTruthy();
    expect(ctx.config).toBeTruthy();
  });
});
