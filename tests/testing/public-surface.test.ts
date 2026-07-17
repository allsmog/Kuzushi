import { describe, expect, expectTypeOf, it, vi } from "vitest";
import type {
  CopilotModule,
  DagContext,
  DagDatabase,
  ExecutionContext,
  ToolResult,
} from "../../src/modules/index.js";
import type { MockToolContextOverrides } from "../../src/testing/index.js";
import * as testingSdk from "../../src/testing/index.js";
import {
  assertToolResult,
  createFakeRuntime,
  createMockBus,
  createMockEventScope,
  createMockHostInfo,
  createMockOptionStore,
  createMockRunArtifactStore,
  createMockToolContext,
  createMockUiStore,
  createMockWorkspace,
  createRecordingLogger,
  createRecordingPrintSink,
  expectModuleShape,
  getRecordedActivity,
  getRecordedOutput,
  ModuleShapeError,
  noopRuntime,
} from "../../src/testing/index.js";

const queryOptions = { cwd: "/fixture", model: "test:model" };

async function collectRuntimeMessages(
  runtime: typeof noopRuntime,
  prompt: string,
): Promise<unknown[]> {
  const messages: unknown[] = [];
  for await (const message of runtime.query({ prompt, options: queryOptions })) {
    messages.push(message);
  }
  return messages;
}

function validModule(): CopilotModule {
  return {
    id: "fixture",
    displayName: "Fixture",
    category: "defense",
    version: "1.0.0",
    description: "Exercises the public testing surface.",
    tools: [
      {
        name: "fixture:scan",
        description: "Runs a fixture scan.",
        inputSchema: { type: "object" },
        headless: true,
        async execute() {
          return { ok: true, output: "done" };
        },
      },
    ],
  };
}

describe("kuzushi/testing public barrel", () => {
  it("exports every documented runtime helper", () => {
    expect(Object.keys(testingSdk).sort()).toEqual([
      "ModuleShapeError",
      "assertToolResult",
      "createFakeRuntime",
      "createMockBus",
      "createMockEventScope",
      "createMockHostInfo",
      "createMockOptionStore",
      "createMockRunArtifactStore",
      "createMockToolContext",
      "createMockUiStore",
      "createMockWorkspace",
      "createRecordingLogger",
      "createRecordingPrintSink",
      "expectModuleShape",
      "getRecordedActivity",
      "getRecordedOutput",
      "noopRuntime",
    ]);
  });

  it("keeps the module and DAG database contracts structural", () => {
    const db: DagDatabase = {
      prepare() {
        return {
          run: (...parameters) => ({ changes: parameters.length }),
          get: (...parameters) => parameters[0],
          all: (...parameters) => [...parameters],
        };
      },
    };
    const dag: DagContext = {
      runId: "run-1",
      repoRoot: "/repo",
      repoName: "fixture",
      db,
      upstreamOutputs: new Map([["fixture:seed", { ok: true }]]),
    };

    expect(dag.db?.prepare("select 1").all("value")).toEqual(["value"]);
    expectTypeOf(db).toMatchTypeOf<DagDatabase>();
    expectTypeOf(dag).toMatchTypeOf<DagContext>();
  });
});

describe("context and host helpers", () => {
  it("creates isolated host defaults and honors explicit empty overrides", () => {
    const first = createMockHostInfo();
    const second = createMockHostInfo();
    const custom = createMockHostInfo({ sdkVersion: "1.2.3", capabilities: [] });

    expect(first.sdkVersion).toBe("0.0.0-test");
    expect(first.capabilities).toContain("workspace");
    expect(first.capabilities).not.toBe(second.capabilities);
    expect(custom).toEqual({ sdkVersion: "1.2.3", capabilities: new Set() });
  });

  it("records default activity and output calls in order", () => {
    const ctx = createMockToolContext({ cwd: "/repo", target: "/repo/src" });
    ctx.reportActivity?.("discovering");
    ctx.reportActivity?.("scanning", { phase: "scan", step: 2, total: 4 });
    ctx.reportOutput?.("first line");
    ctx.reportOutput?.("second line");

    expect(ctx.cwd).toBe("/repo");
    expect(ctx.target).toBe("/repo/src");
    expect(getRecordedActivity(ctx)).toEqual([
      { description: "discovering" },
      { description: "scanning", meta: { phase: "scan", step: 2, total: 4 } },
    ]);
    expect(getRecordedOutput(ctx)).toEqual(["first line", "second line"]);
    expect(Object.keys(ctx)).not.toContain("__activityCalls");
    expect(Object.keys(ctx)).not.toContain("__outputCalls");
  });

  it("gives explicit overrides precedence while retaining config defaults", () => {
    const runtime = createFakeRuntime();
    const bus = createMockBus();
    const logger = createRecordingLogger();
    const uiStore = createMockUiStore();
    const datastore = createMockOptionStore();
    const workspace = createMockWorkspace();
    const events = createMockEventScope();
    const print = createRecordingPrintSink();
    const runArtifacts = createMockRunArtifactStore();
    const activity = vi.fn();
    const output = vi.fn();
    const seedTaskOutputs = new Map<string, unknown>([["seed", 1]]);

    const ctx = createMockToolContext({
      cwd: "/custom",
      runtime,
      bus,
      logger,
      uiStore,
      datastore,
      workspace,
      events,
      print,
      runArtifacts,
      reportActivity: activity,
      reportOutput: output,
      seedTaskOutputs,
      config: { model: "custom:model" },
      host: { sdkVersion: "9.0.0", capabilities: new Set() },
    });

    expect(ctx).toMatchObject({
      cwd: "/custom",
      runtime,
      bus,
      logger,
      uiStore,
      datastore,
      workspace,
      events,
      print,
      runArtifacts,
      seedTaskOutputs,
    });
    expect(ctx.config.model).toBe("custom:model");
    expect(ctx.config.tasks).toEqual([]);
    expect(ctx.host).toEqual({ sdkVersion: "9.0.0", capabilities: new Set() });
    ctx.reportActivity?.("custom");
    ctx.reportOutput?.("custom");
    expect(activity).toHaveBeenCalledWith("custom");
    expect(output).toHaveBeenCalledWith("custom");
    expect(getRecordedActivity(ctx)).toEqual([]);
    expect(getRecordedOutput(ctx)).toEqual([]);
  });

  it("builds a complete default execution context", () => {
    const ctx = createMockToolContext();
    expect(ctx.runtime).toBe(noopRuntime);
    expect(ctx.host?.capabilities).toEqual(
      new Set(["workspace", "ui-store", "datastore", "module-events", "print-sink"]),
    );
    expect(ctx.logger).toBeDefined();
    expect(ctx.uiStore).toBeDefined();
    expect(ctx.datastore).toBeDefined();
    expect(ctx.workspace).toBeDefined();
    expect(ctx.events).toBeDefined();
    expect(ctx.print).toBeDefined();
    expect(ctx.seedTaskOutputs).toEqual(new Map());
    expect(ctx.runArtifacts).toBeUndefined();
    expectTypeOf(ctx).toMatchTypeOf<ExecutionContext>();
  });

  it.each([
    "runtime",
    "logger",
    "uiStore",
    "datastore",
    "workspace",
    "events",
    "print",
    "reportActivity",
    "reportOutput",
  ] as const)("preserves an explicit undefined %s override", (field) => {
    const overrides = { [field]: undefined } as MockToolContextOverrides;
    const ctx = createMockToolContext(overrides);

    expect(ctx[field]).toBeUndefined();
  });

  it.each([
    ["workspace", "workspace"],
    ["uiStore", "ui-store"],
    ["datastore", "datastore"],
    ["events", "module-events"],
    ["print", "print-sink"],
  ] as const)("removes the inferred %s capability with its handle", (field, capability) => {
    const overrides = { [field]: undefined } as MockToolContextOverrides;
    const ctx = createMockToolContext(overrides);

    expect(ctx.host?.capabilities).not.toContain(capability);
    expect(ctx.host?.capabilities.size).toBe(4);
  });

  it("models a headless context while allowing explicit handles", () => {
    const headless = createMockToolContext({ profile: "headless" });
    const workspace = createMockWorkspace();
    const withWorkspace = createMockToolContext({ profile: "headless", workspace });

    expect(headless).toMatchObject({
      runtime: undefined,
      logger: undefined,
      uiStore: undefined,
      datastore: undefined,
      workspace: undefined,
      events: undefined,
      print: undefined,
      reportActivity: undefined,
      reportOutput: undefined,
    });
    expect(headless.bus).toBeDefined();
    expect(headless.config).toBeDefined();
    expect(headless.cwd).toBe(process.cwd());
    expect(headless.host?.capabilities).toEqual(new Set());
    expect(getRecordedActivity(headless)).toEqual([]);
    expect(getRecordedOutput(headless)).toEqual([]);
    expect(withWorkspace.workspace).toBe(workspace);
    expect(withWorkspace.host?.capabilities).toEqual(new Set(["workspace"]));
  });

  it("supports omitting host metadata entirely", () => {
    const ctx = createMockToolContext({ host: undefined });

    expect(ctx.host).toBeUndefined();
  });

  it.each([
    ["workspace", "workspace"],
    ["uiStore", "ui-store"],
    ["datastore", "datastore"],
    ["events", "module-events"],
    ["print", "print-sink"],
    ["runArtifacts", "run-artifacts"],
  ] as const)("rejects an explicit %s capability without its handle", (field, capability) => {
    const overrides = {
      [field]: undefined,
      host: { capabilities: new Set([capability]) },
    } as MockToolContextOverrides;

    expect(() => createMockToolContext(overrides)).toThrow(
      `host capability ${capability} needs ctx.${field}`,
    );
  });

  it("infers injected handle capabilities unless an explicit host overrides them", () => {
    const runArtifacts = createMockRunArtifactStore();
    const inferred = createMockToolContext({ runArtifacts });
    const explicitEmpty = createMockToolContext({
      runArtifacts,
      host: { sdkVersion: "1.0.0", capabilities: new Set() },
    });

    expect(inferred.host?.capabilities).toContain("run-artifacts");
    expect(explicitEmpty.host).toEqual({ sdkVersion: "1.0.0", capabilities: new Set() });
  });

  it("infers handle capabilities when an explicit host only changes its version", () => {
    const ctx = createMockToolContext({ host: { sdkVersion: "1.2.3" } });

    expect(ctx.host).toEqual({
      sdkVersion: "1.2.3",
      capabilities: new Set(["workspace", "ui-store", "datastore", "module-events", "print-sink"]),
    });
  });
});

describe("message bus and event helpers", () => {
  it("records bus emissions and dispatches subscribers in registration order", async () => {
    const bus = createMockBus();
    const observed: unknown[] = [];
    const first = async (event: unknown) => {
      observed.push(["first", event]);
    };
    const second = (event: unknown) => {
      observed.push(["second", event]);
    };
    bus.subscribe("scan:done", first);
    bus.subscribe("scan:done", second);

    await bus.emit("scan:done", { count: 2 });
    await bus.publish({
      type: "scan:done",
      meta: { id: "event-1", timestamp: "now", runId: "run-1" },
      payload: { count: 3 },
    });
    bus.unsubscribe("scan:done", first);
    await bus.emit("scan:done", { count: 4 });

    expect(bus.emitted).toEqual([
      { eventType: "scan:done", payload: { count: 2 } },
      { eventType: "scan:done", payload: { count: 3 } },
      { eventType: "scan:done", payload: { count: 4 } },
    ]);
    expect(observed).toEqual([
      ["first", bus.published[0]],
      ["second", bus.published[0]],
      ["first", bus.published[1]],
      ["second", bus.published[1]],
      ["second", bus.published[2]],
    ]);
    expect(bus.published[1]).toEqual({
      type: "scan:done",
      meta: { id: "event-1", timestamp: "now", runId: "run-1" },
      payload: { count: 3 },
    });
    expect(bus.published[0]).toMatchObject({
      type: "scan:done",
      meta: { id: "mock-event-1", runId: "test-run" },
      payload: { count: 2 },
    });
  });

  it("waits on the same envelope stream used by publish", async () => {
    const bus = createMockBus();
    const waiting = bus.waitFor(
      "scan:done",
      (event) => (event.payload as { count?: number }).count === 2,
      100,
    );
    await bus.publish({
      type: "scan:done",
      meta: { id: "skip", timestamp: "now", runId: "run-1" },
      payload: { count: 1 },
    });
    const expected = {
      type: "scan:done",
      meta: { id: "match", timestamp: "later", runId: "run-1" },
      payload: { count: 2 },
    };
    await bus.publish(expected);

    await expect(waiting).resolves.toEqual(expected);
    await expect(bus.waitFor("never", undefined, 1)).rejects.toThrow(/timed out/);
  });

  it("unsubscribes safely and stops dispatch after shutdown", async () => {
    const bus = createMockBus();
    const handler = vi.fn();
    bus.unsubscribe("missing", handler);
    bus.subscribe("event", handler);
    await bus.close();
    await bus.emit("event", 1);
    expect(handler).not.toHaveBeenCalled();
    expect(bus.emitted).toEqual([{ eventType: "event", payload: 1 }]);
  });

  it("supports persistent and once event handlers and captures failures", async () => {
    const events = createMockEventScope();
    const calls: string[] = [];
    const syncError = new Error("sync handler failed");
    const asyncError = new Error("async handler failed");
    const remove = events.on("tick", () => calls.push("persistent"));
    events.once("tick", () => calls.push("once"));
    events.on("tick", () => {
      throw syncError;
    });
    events.on("tick", async () => {
      throw asyncError;
    });

    events.emit("tick", { n: 1 });
    events.emit("tick", { n: 2 });
    await Promise.resolve();
    await Promise.resolve();
    remove();
    remove();
    events.emit("tick", { n: 3 });

    expect(calls).toEqual(["persistent", "once", "persistent"]);
    expect(events.emitted).toHaveLength(3);
    expect(events.errors.filter(({ error }) => error === syncError)).toHaveLength(3);
    expect(events.errors.filter(({ error }) => error === asyncError)).toHaveLength(2);
    events.clear();
    expect(events.emitted).toEqual([]);
    expect(events.errors).toEqual([]);
    events.disposeAll();
    events.emit("tick", { n: 4 });
    expect(events.emitted).toEqual([{ event: "tick", payload: { n: 4 } }]);
  });
});

describe("recording stores and sinks", () => {
  it("normalizes option keys and supports seed, set, and clear", () => {
    const store = createMockOptionStore({ model: "one", COUNT: 2 });
    expect(store.get("MODEL")).toBe("one");
    expect(store.get<number>("count")).toBe(2);
    expect(store.has("MoDeL")).toBe(true);
    expect(store.set("model", "two")).toBeNull();
    store.seed("payload", { ok: true });
    expect([...store.entries]).toEqual([
      ["MODEL", "two"],
      ["COUNT", 2],
      ["PAYLOAD", { ok: true }],
    ]);
    store.clear();
    expect(store.entries.size).toBe(0);
    expect(store.has("model")).toBe(false);
  });

  it("records logger calls by level and in call order", () => {
    const logger = createRecordingLogger();
    logger.info("one");
    logger.warn("two", { finding: 2 });
    logger.error("three");
    logger.debug("four", { verbose: true });

    expect(logger.records.map(({ level, message }) => `${level}:${message}`)).toEqual([
      "info:one",
      "warn:two",
      "error:three",
      "debug:four",
    ]);
    expect(logger.filter("warn")).toEqual([
      { level: "warn", message: "two", meta: { finding: 2 } },
    ]);
    logger.clear();
    expect(logger.records).toEqual([]);
  });

  it("records print levels and captures only output produced by the callback", async () => {
    const print = createRecordingPrintSink();
    print.status("before");
    const captured = await print.capture(async () => {
      print.good("good");
      await Promise.resolve();
      print.error("error");
      print.warn("warn");
      print.line("line");
    });

    expect(captured).toBe("good\nerror\nwarn\nline");
    expect(print.records.map(({ level }) => level)).toEqual([
      "status",
      "good",
      "error",
      "warn",
      "line",
    ]);
    expect(print.filter("good")).toEqual([{ level: "good", text: "good" }]);
    print.clear();
    expect(print.records).toEqual([]);
  });

  it("records safe run artifacts and rejects path escapes", () => {
    const store = createMockRunArtifactStore({
      runId: "run-7",
      moduleId: "fixture",
      root: "/virtual/run/fixture",
    });
    expect(store.path("nested/report..json")).toBe("/virtual/run/fixture/nested/report..json");
    expect(store.write("report.json", "{}")).toBe("/virtual/run/fixture/report.json");
    const bytes = new Uint8Array([1, 2]);
    store.write("nested/data.bin", bytes);
    expect(store.writes).toEqual([
      { name: "report.json", content: "{}" },
      { name: "nested/data.bin", content: bytes },
    ]);
    for (const name of ["", "/absolute", "\\absolute", "C:\\absolute", "../escape", "a/../b"]) {
      expect(() => store.path(name)).toThrow(/RunArtifactStore:/);
    }
    store.clear();
    expect(store.writes).toEqual([]);

    const defaults = createMockRunArtifactStore();
    expect(defaults).toMatchObject({ runId: "test-run", moduleId: "test-module" });
    expect(defaults.path("result.json")).toContain("/test-run/test-module/result.json");
  });

  it("shallow-merges UI patches and supports seed and clear", () => {
    const ui = createMockUiStore({ phase: "idle", nested: { old: true } });
    ui.update({ phase: "scan", count: 1 });
    ui.update({ nested: { fresh: true } });
    expect(ui.patches).toEqual([{ phase: "scan", count: 1 }, { nested: { fresh: true } }]);
    expect(ui.getState()).toEqual({ phase: "scan", count: 1, nested: { fresh: true } });
    expect(ui.state).toEqual(ui.getState());
    ui.seed({ phase: "seeded" });
    expect(ui.state).toEqual({ phase: "seeded" });
    ui.clear();
    expect(ui.state).toEqual({});
    expect(ui.patches).toEqual([]);
  });

  it("records workspace writes and makes created vulns immediately readable", () => {
    const workspace = createMockWorkspace();
    expect(workspace.hosts.findByAddress?.("workspace", "127.0.0.1")).toBeUndefined();
    expect(workspace.rawDb()).toBeUndefined();
    workspace.hosts.upsert({ address: "127.0.0.1" });
    workspace.services.upsert({ port: 443 });
    workspace.notes.create({ text: "note" });
    workspace.seedVulns([{ id: "seed" }]);
    workspace.vulns.create?.({ id: "created" });

    expect(workspace.hostUpserts).toEqual([{ address: "127.0.0.1" }]);
    expect(workspace.serviceUpserts).toEqual([{ port: 443 }]);
    expect(workspace.noteCreates).toEqual([{ text: "note" }]);
    expect(workspace.vulnCreates).toEqual([{ id: "created" }]);
    expect(workspace.vulns.listForWorkspace("workspace")).toEqual([
      { id: "seed" },
      { id: "created" },
    ]);
    expect(workspace.vulnRows).toEqual([{ id: "seed" }, { id: "created" }]);
    workspace.clear();
    expect(workspace.hostUpserts).toEqual([]);
    expect(workspace.serviceUpserts).toEqual([]);
    expect(workspace.noteCreates).toEqual([]);
    expect(workspace.vulnCreates).toEqual([]);
    expect(workspace.vulnRows).toEqual([]);
  });
});

describe("runtime helpers", () => {
  it("provides a noop runtime that yields no messages", async () => {
    expect(noopRuntime.id).toBe("noop-runtime");
    expect(await collectRuntimeMessages(noopRuntime, "ignored")).toEqual([]);
  });

  it("matches scripted responses, emits tool-use messages, and records calls", async () => {
    const runtime = createFakeRuntime([
      { match: "first", output: "first match" },
      {
        match: /triage/i,
        output: "triaged",
        structuredOutput: { verdict: true },
        costUsd: 0.02,
        toolUse: { name: "Read", input: { path: "a.ts" }, toolUseId: "tool-7" },
      },
    ]);

    const messages = await collectRuntimeMessages(runtime, "please TRIAGE this");
    expect(messages).toEqual([
      {
        type: "assistant",
        content: [
          { type: "text", text: "triaged" },
          { type: "tool_use", id: "tool-7", name: "Read", input: { path: "a.ts" } },
        ],
      },
      { type: "tool-result", toolUseId: "tool-7", isError: false, content: "" },
      {
        type: "result",
        subtype: "success",
        result: "triaged",
        structuredOutput: { verdict: true },
        totalCostUsd: 0.02,
      },
    ]);
    expect(runtime.calls).toEqual([{ prompt: "please TRIAGE this", options: queryOptions }]);
    runtime.clear();
    expect(runtime.calls).toEqual([]);
  });

  it("uses generated tool ids and a deterministic unmatched fallback", async () => {
    const runtime = createFakeRuntime([
      { match: /use tool/, output: "", toolUse: { name: "Read", input: {} } },
    ]);
    const toolMessages = await collectRuntimeMessages(runtime, "use tool");
    expect(toolMessages).toContainEqual({
      type: "tool-result",
      toolUseId: "tu_1",
      isError: false,
      content: "",
    });
    expect(await collectRuntimeMessages(runtime, "unmatched")).toEqual([
      { type: "assistant", content: [] },
      {
        type: "result",
        subtype: "success",
        result: "",
        structuredOutput: undefined,
        totalCostUsd: 0,
      },
    ]);
  });

  it.each([
    /triage/g,
    /triage/y,
  ])("matches the same stateful regex repeatedly: %s", async (match) => {
    const runtime = createFakeRuntime([{ match, output: "matched" }]);

    for (let call = 0; call < 3; call += 1) {
      const messages = await collectRuntimeMessages(runtime, "triage request");
      expect(messages).toContainEqual(
        expect.objectContaining({ type: "result", subtype: "success", result: "matched" }),
      );
      expect(match.lastIndex).toBe(0);
    }
  });
});

describe("assertions and module-shape helpers", () => {
  it("accepts every ToolResult expectation form", () => {
    const result: ToolResult = {
      ok: true,
      output: "scan complete: 2 findings",
      data: { findings: [1, 2] },
      costUsd: 0.01,
    };
    expect(() =>
      assertToolResult(result, {
        ok: true,
        outputContains: ["scan complete", /\d+ findings/],
        outputMatches: /^scan complete/,
        dataShape: (data) => Array.isArray((data as { findings?: unknown }).findings),
        costUsdMax: 0.02,
      }),
    ).not.toThrow();
    expect(() =>
      assertToolResult({ ok: true, output: "ok", costUsd: 0 }, { costUsdMax: 0 }),
    ).not.toThrow();
    expect(() => assertToolResult(result, { outputContains: "complete" })).not.toThrow();
    expect(() => assertToolResult(result, {})).not.toThrow();
  });

  it.each([
    ["missing", undefined, /measured numeric costUsd, got missing/],
    ["nonnumeric", "0", /measured numeric costUsd, got string "0"/],
    ["NaN", Number.NaN, /finite costUsd, got NaN/],
    ["positive Infinity", Number.POSITIVE_INFINITY, /finite costUsd, got Infinity/],
    ["negative Infinity", Number.NEGATIVE_INFINITY, /finite costUsd, got -Infinity/],
    ["negative", -0.01, /nonnegative costUsd, got -0.01/],
  ])("rejects a %s measured cost when a bound is requested", (_name, costUsd, message) => {
    const result = { ok: true, output: "ok", costUsd } as ToolResult;

    expect(() => assertToolResult(result, { costUsdMax: 1 })).toThrow(message as RegExp);
  });

  it.each([
    ["NaN", Number.NaN],
    ["positive Infinity", Number.POSITIVE_INFINITY],
    ["negative Infinity", Number.NEGATIVE_INFINITY],
    ["negative", -0.01],
  ])("rejects a %s cost bound", (_name, costUsdMax) => {
    expect(() => assertToolResult({ ok: true, output: "ok", costUsd: 0 }, { costUsdMax })).toThrow(
      `costUsdMax must be a finite nonnegative number, got ${String(costUsdMax)}`,
    );
  });

  it("accepts finite zero and measured costs within a valid range", () => {
    expect(() =>
      assertToolResult({ ok: true, output: "ok", costUsd: 0 }, { costUsdMax: 0 }),
    ).not.toThrow();
    expect(() =>
      assertToolResult({ ok: true, output: "ok", costUsd: 0.25 }, { costUsdMax: 0.5 }),
    ).not.toThrow();
  });

  it("asserts observed subtotal and unresolved provider spend without inventing exact cost", () => {
    const result: ToolResult = {
      ok: true,
      output: "patch complete with unresolved provider spend",
      observedCostUsd: 0.25,
      providerSpendUnresolved: true,
    };

    expect(() =>
      assertToolResult(result, {
        observedCostUsdMax: 0.3,
        providerSpendUnresolved: true,
      }),
    ).not.toThrow();
    expect(() => assertToolResult(result, { costUsdMax: 0.3 })).toThrow(
      /measured numeric costUsd, got missing/,
    );
  });

  it("reuses global and sticky assertion regexes without cursor drift", () => {
    const result = { ok: true, output: "scan complete: 2 findings" };
    const contains = /\d+ findings/g;
    const matches = /^scan complete/y;
    const expectations = { outputContains: contains, outputMatches: matches };

    for (let call = 0; call < 3; call += 1) {
      expect(() => assertToolResult(result, expectations)).not.toThrow();
      expect(contains.lastIndex).toBe(0);
      expect(matches.lastIndex).toBe(0);
    }
  });

  it.each([
    ["object", null, {}, /expected a ToolResult object/],
    ["ok", { ok: false, output: "no" }, { ok: true }, /expected ok=true/],
    ["string contains", { ok: true, output: "no" }, { outputContains: "yes" }, /contain "yes"/],
    ["regex contains", { ok: true, output: "no" }, { outputContains: /yes/ }, /contain yes/],
    ["output match", { ok: true, output: "no" }, { outputMatches: /^yes/ }, /match \/\^yes\//],
    [
      "data shape false",
      { ok: true, output: "no", data: {} },
      { dataShape: () => false },
      /predicate returned false/,
    ],
    ["cost", { ok: true, output: "no", costUsd: 2 }, { costUsdMax: 1 }, /costUsd <= 1/],
  ])("reports a descriptive %s mismatch", (_name, result, expectations, message) => {
    expect(() =>
      assertToolResult(
        result as ToolResult,
        expectations as Parameters<typeof assertToolResult>[1],
      ),
    ).toThrow(message as RegExp);
  });

  it("reports thrown data predicates and truncates oversized result dumps", () => {
    expect(() =>
      assertToolResult(
        { ok: true, output: "x".repeat(500), data: {} },
        {
          dataShape: () => {
            throw "shape exploded";
          },
        },
      ),
    ).toThrow(/dataShape predicate threw: shape exploded[\s\S]*…/);
  });

  it("accepts valid modules and narrows unknown values", () => {
    const candidate: unknown = validModule();
    expect(() => expectModuleShape(candidate)).not.toThrow();
    expectTypeOf(candidate).toMatchTypeOf<CopilotModule>();
  });

  it("turns loader failures into structured ModuleShapeError values", () => {
    const malformed = {
      id: "fixture",
      displayName: "Fixture",
      category: "defense",
      version: "1.0.0",
      tools: [{ name: "other:Bad Name" }, { name: "other:Bad Name" }],
    };
    let caught: unknown;
    try {
      expectModuleShape(malformed);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ModuleShapeError);
    const shapeError = caught as ModuleShapeError;
    expect(shapeError.name).toBe("ModuleShapeError");
    expect(shapeError.issues.length).toBeGreaterThan(1);
    expect(shapeError.cause).toBeDefined();
    expect(shapeError.message).toMatch(/shape issues/);

    expect(() => expectModuleShape(null)).toThrowError(
      expect.objectContaining({
        issues: ["Module must export an object with CopilotModule shape."],
      }),
    );
  });

  it("constructs single- and multi-issue ModuleShapeError values", () => {
    const single = new ModuleShapeError(["one"]);
    const cause = new Error("cause");
    const multiple = new ModuleShapeError(["one", "two"], cause);
    expect(single.message).toContain("Module shape invalid: one");
    expect(single.cause).toBeUndefined();
    expect(multiple.message).toContain("2 shape issues");
    expect(multiple.cause).toBe(cause);
    expect(multiple).toBeInstanceOf(Error);
  });
});
