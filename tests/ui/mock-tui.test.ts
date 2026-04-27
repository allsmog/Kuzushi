/**
 * Mock-TUI smoke tests — boot every registered scenario through the
 * plain-renderer and assert no crashes plus expected view-label tokens.
 *
 * Goes through `applySeedToStore` (the same merge `mountMockShell` uses
 * at runtime) so the test exercises the same code path as `tsx
 * scripts/mock-tui.ts <scenario>` minus the Ink mount.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { applySeedToStore, listScenarios } from "../../src/copilot/mock-tui/index.js";
// Side-effect: registers all scenarios into the SCENARIOS registry.
import "../../src/copilot/mock-tui/scenarios/index.js";
import { buildSlashCommandRouter } from "../../src/copilot/mock-tui/slash-commands.js";
import { registerPlainTextRenderer } from "../../src/ui/plain-renderer.js";
import { createUIStore } from "../../src/ui/state.js";

function attach(store: ReturnType<typeof createUIStore>): {
  lines: string[];
  unsub: () => void;
} {
  const lines: string[] = [];
  const unsub = registerPlainTextRenderer(store, {
    write: (line: string) => {
      lines.push(line);
    },
  });
  return { lines, unsub };
}

const prevNoColor = process.env.NO_COLOR;

describe("mock-tui scenarios", () => {
  beforeEach(() => {
    process.env.NO_COLOR = "1";
  });
  afterEach(() => {
    if (prevNoColor === undefined) delete process.env.NO_COLOR;
    else process.env.NO_COLOR = prevNoColor;
  });

  it("registers at least the v1 scenarios", () => {
    const ids = listScenarios().map((s) => s.id);
    expect(ids).toEqual(
      expect.arrayContaining(["catalog", "findings-many", "module-sast", "sast-tasks"]),
    );
  });

  it("catalog scenario emits the catalog heading + module rows", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    const scenario = listScenarios().find((s) => s.id === "catalog");
    expect(scenario).toBeDefined();
    if (!scenario) return;
    applySeedToStore(store, scenario.seed());
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("# CATALOG");
    expect(joined).toContain("## OFFENSE");
    expect(joined).toMatch(/- sast/);
  });

  it("findings-many scenario surfaces 50 findings via the findings view", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    const scenario = listScenarios().find((s) => s.id === "findings-many");
    expect(scenario).toBeDefined();
    if (!scenario) return;
    applySeedToStore(store, scenario.seed());
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("# FINDINGS");
    expect(joined).toContain("F-0001");
    expect(joined).toContain("F-0050");
  });

  it("module-sast scenario opens ModuleHome for sast", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    const scenario = listScenarios().find((s) => s.id === "module-sast");
    expect(scenario).toBeDefined();
    if (!scenario) return;
    applySeedToStore(store, scenario.seed());
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("# MODULE  sast");
    expect(joined).toContain("## tools");
  });

  it("sast-tasks scenario emits the task selector view", () => {
    const store = createUIStore();
    const { lines, unsub } = attach(store);
    const scenario = listScenarios().find((s) => s.id === "sast-tasks");
    expect(scenario).toBeDefined();
    if (!scenario) return;
    applySeedToStore(store, scenario.seed());
    unsub();
    const joined = lines.join("\n");
    expect(joined).toContain("# SAST TASKS");
    expect(joined).toContain("profile standard · auto + denylist");
    expect(joined).toContain("active: codeql · Space allows codeql.");
  });

  it("every registered scenario seeds without crashing the plain renderer", () => {
    for (const scenario of listScenarios()) {
      const store = createUIStore();
      const { unsub } = attach(store);
      expect(() => {
        applySeedToStore(store, scenario.seed());
      }).not.toThrow();
      unsub();
    }
  });
});

describe("mock-tui slash-command router", () => {
  beforeEach(() => {
    process.env.NO_COLOR = "1";
  });
  afterEach(() => {
    if (prevNoColor === undefined) delete process.env.NO_COLOR;
    else process.env.NO_COLOR = prevNoColor;
  });

  function bootCatalog(): {
    store: ReturnType<typeof createUIStore>;
    onInput: (input: string) => void;
  } {
    const store = createUIStore();
    const scenario = listScenarios().find((s) => s.id === "catalog");
    if (!scenario) throw new Error("catalog scenario missing");
    const onInput = buildSlashCommandRouter(store, { onExit: () => {} });
    applySeedToStore(store, scenario.seed(), { onInput });
    return { store, onInput };
  }

  it("/findings switches to the findings view", () => {
    const { store, onInput } = bootCatalog();
    onInput("/findings");
    expect(store.getState().shell?.shellView).toBe("findings");
  });

  it("/use <id> focuses the module and switches to module view", () => {
    const { store, onInput } = bootCatalog();
    onInput("/use sast");
    const shell = store.getState().shell;
    expect(shell?.shellView).toBe("module");
    expect(shell?.focusedModule).toBe("sast");
  });

  it("/tasks opens the SAST task selector", () => {
    const { store, onInput } = bootCatalog();
    onInput("/tasks");
    const shell = store.getState().shell;
    expect(shell?.shellView).toBe("sast-tasks");
    expect(shell?.focusedModule).toBe("sast");
  });

  it("/task commands update mock SAST task state", () => {
    const { store, onInput } = bootCatalog();
    onInput("/tasks");
    onInput("/task block codeql");
    expect(store.getState().shell?.moduleOptions["sast:scan"]?.disabledTasks).toEqual(["codeql"]);
    onInput("/task toggle codeql");
    expect(store.getState().shell?.moduleOptions["sast:scan"]?.disabledTasks).toBeUndefined();
    onInput("/task mode manual");
    expect(store.getState().shell?.moduleOptions["sast:scan"]?.taskMode).toBe("manual");
  });

  it("/threats stride sets the stride tab", () => {
    const { store, onInput } = bootCatalog();
    onInput("/threats stride");
    const shell = store.getState().shell;
    expect(shell?.shellView).toBe("threats");
    expect(shell?.threatTab).toBe("stride");
  });

  it("bare digit cycles threat tabs while in threats view", () => {
    const { store, onInput } = bootCatalog();
    onInput("/threats dfd");
    onInput("3");
    const shell = store.getState().shell;
    expect(shell?.threatTab).toBe("stories");
  });

  it("/back pops to the prior view", () => {
    const { store, onInput } = bootCatalog();
    onInput("/findings");
    onInput("/use sast");
    onInput("/back");
    expect(store.getState().shell?.shellView).toBe("findings");
    onInput("/back");
    expect(store.getState().shell?.shellView).toBe("catalog");
  });

  it("/back with empty stack writes an info history entry, no crash", () => {
    const { store, onInput } = bootCatalog();
    onInput("/back");
    const shell = store.getState().shell;
    expect(shell?.shellView).toBe("catalog");
    const lastEntry = shell?.history.at(-1);
    expect(lastEntry?.text).toMatch(/no prior view/);
  });

  it("/quit invokes the supplied onExit handler", () => {
    const store = createUIStore();
    const scenario = listScenarios().find((s) => s.id === "catalog");
    if (!scenario) throw new Error("catalog scenario missing");
    let quitCalls = 0;
    const onInput = buildSlashCommandRouter(store, {
      onExit: () => {
        quitCalls += 1;
      },
    });
    applySeedToStore(store, scenario.seed(), { onInput });
    onInput("/quit");
    expect(quitCalls).toBe(1);
    onInput(":q");
    expect(quitCalls).toBe(2);
  });

  it("unknown commands write an info history entry instead of crashing", () => {
    const { store, onInput } = bootCatalog();
    onInput("/something-not-real");
    const shell = store.getState().shell;
    expect(shell?.shellView).toBe("catalog");
    const lastEntry = shell?.history.at(-1);
    expect(lastEntry?.text).toMatch(/command not available in mock mode/);
  });

  it("/tune without a focused module emits a hint instead of switching", () => {
    const { store, onInput } = bootCatalog();
    onInput("/tune");
    const shell = store.getState().shell;
    expect(shell?.shellView).toBe("catalog");
    const lastEntry = shell?.history.at(-1);
    expect(lastEntry?.text).toMatch(/requires a focused module/);
  });
});

describe("mock-tui playback", () => {
  beforeEach(() => {
    process.env.NO_COLOR = "1";
  });
  afterEach(() => {
    if (prevNoColor === undefined) delete process.env.NO_COLOR;
    else process.env.NO_COLOR = prevNoColor;
  });

  it("module-run-active scenario streams evidence and finalizes via playback", async () => {
    const store = createUIStore();
    const scenario = listScenarios().find((s) => s.id === "module-run-active");
    expect(scenario).toBeDefined();
    if (!scenario) return;
    expect(scenario.playback).toBeDefined();

    applySeedToStore(store, scenario.seed());
    const initial = store.getState().shell?.moduleRun;
    expect(initial?.status).toBe("running");
    const initialEvidenceLength = initial?.evidenceTail.length ?? 0;

    const stop = scenario.playback?.(store);
    try {
      // Wait long enough for every step in the timer chain to fire (~7s).
      await new Promise<void>((resolve) => setTimeout(resolve, 7500));
    } finally {
      stop?.();
    }

    const finalRun = store.getState().shell?.moduleRun;
    expect(finalRun?.status).toBe("done");
    expect(finalRun?.evidenceTail.length ?? 0).toBeGreaterThan(initialEvidenceLength);
    expect(finalRun?.costUsd).toBeGreaterThan(0);
  }, 15_000);

  it("playback cleanup stops timer chain (no late writes after stop)", async () => {
    const store = createUIStore();
    const scenario = listScenarios().find((s) => s.id === "module-run-active");
    if (!scenario?.playback) {
      throw new Error("module-run-active scenario missing playback");
    }

    applySeedToStore(store, scenario.seed());
    const stop = scenario.playback(store);
    // Stop immediately, before the first timer fires.
    stop();
    const beforeStatus = store.getState().shell?.moduleRun?.status;
    await new Promise<void>((resolve) => setTimeout(resolve, 2000));
    const afterStatus = store.getState().shell?.moduleRun?.status;
    expect(afterStatus).toBe(beforeStatus);
    expect(afterStatus).toBe("running");
  }, 5_000);
});
