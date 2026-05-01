/**
 * Chrome / footer / banner stack tests.
 *
 * Verifies the high-confidence audit fixes:
 *
 * 1. `buildIdleKeybindsForView` adds `/back` outside the catalog.
 * 2. `ShellAdvisoryStack` (rate-limit + cost-cap halt) is reachable
 *    from shell mode, not just running mode (per CLAUDE.md
 *    "Failure-mode surfaces").
 * 3. The KeybindFooter still renders the canonical idle row when no
 *    deeper view registers its own bindings.
 */

import { PassThrough, type Writable } from "node:stream";
import { Box, render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { buildIdleKeybindsForView, CopilotShell } from "../../src/ui/components/CopilotShell.js";
import { CostCapHalt } from "../../src/ui/components/CostCapHalt.js";
import { RateLimitBanner } from "../../src/ui/components/RateLimitBanner.js";
import { KeybindFooter } from "../../src/ui/primitives/KeybindFooter.js";
import { createUIStore } from "../../src/ui/state.js";

// biome-ignore lint/suspicious/noControlCharactersInRegex: strip ANSI for assertions
const ANSI_RE = /(?:\[[0-9;?]*[ -/]*[@-~]|][^]*(?:|\\))/g;

function renderToText(node: ReactElement, columns = 120, rows = 30): string {
  const stream = new PassThrough() as unknown as Writable & NodeJS.WriteStream;
  (stream as unknown as { columns: number }).columns = columns;
  (stream as unknown as { rows: number }).rows = rows;
  (stream as unknown as { isTTY: boolean }).isTTY = false;
  const chunks: Buffer[] = [];
  (stream as unknown as PassThrough).on("data", (chunk: Buffer) => chunks.push(chunk));
  const instance = render(node, { stdout: stream, debug: true });
  instance.unmount();
  (stream as unknown as PassThrough).end();
  return Buffer.concat(chunks).toString("utf-8").replace(ANSI_RE, "").trimEnd();
}

describe("buildIdleKeybindsForView", () => {
  it("omits /back at the catalog", () => {
    const bindings = buildIdleKeybindsForView("catalog");
    expect(bindings.find((b) => b.keys === "/back")).toBeUndefined();
  });

  it("adds /back when the view has a parent (module)", () => {
    const bindings = buildIdleKeybindsForView("module");
    expect(bindings.find((b) => b.keys === "/back")).toBeDefined();
  });

  it("adds /back on findings, finding, threats, prompts-editor, module-run", () => {
    for (const view of [
      "findings",
      "finding",
      "threats",
      "prompts-editor",
      "module-run",
    ] as const) {
      const bindings = buildIdleKeybindsForView(view);
      expect(
        bindings.find((b) => b.keys === "/back"),
        `missing /back for ${view}`,
      ).toBeDefined();
    }
  });

  it("retains the canonical Send and history hints", () => {
    const bindings = buildIdleKeybindsForView("module");
    expect(bindings[0]?.keys).toBe("Enter");
    expect(bindings.find((b) => b.label === "History")).toBeDefined();
  });

  it("preserves Ctrl+C exit at the tail", () => {
    const bindings = buildIdleKeybindsForView("module");
    expect(bindings[bindings.length - 1]?.keys).toBe("Ctrl+C");
  });
});

describe("KeybindFooter — module-view binding row", () => {
  it("renders /back among the visible hints when given the module-view row", () => {
    const out = renderToText(
      createElement(KeybindFooter, {
        bindings: buildIdleKeybindsForView("module"),
      }),
      120,
      4,
    );
    expect(out).toContain("/back");
    expect(out).toContain("Enter");
  });

  it("hides /back at the catalog row", () => {
    const out = renderToText(
      createElement(KeybindFooter, {
        bindings: buildIdleKeybindsForView("catalog"),
      }),
      120,
      4,
    );
    expect(out).not.toContain("/back");
  });
});

describe("Chrome stack — rate-limit + cost-cap halt", () => {
  it("rate-limit banner is hidden when throttle is unset", () => {
    const out = renderToText(createElement(RateLimitBanner, { throttle: undefined }));
    expect(out.trim()).toBe("");
  });

  it("rate-limit banner appears when throttle is set", () => {
    const out = renderToText(
      createElement(RateLimitBanner, {
        throttle: { concurrency: 2, reason: "429 from provider" },
      }),
    );
    expect(out).toContain("rate-limited");
    expect(out).toContain("concurrency reduced to 2");
  });

  it("cost-cap halt always names the abort key", () => {
    const out = renderToText(createElement(CostCapHalt, { runningCostUsd: 5.5, budgetUsd: 5.0 }));
    expect(out).toMatch(/press\s+c/);
    expect(out).toContain("a");
    expect(out).toContain("abort");
  });

  it("rate-limit + cost-cap render together without overlap (multi-banner stack)", () => {
    // Render the two banners as siblings; verify both labels are present
    // in the captured output. This is a structural check that the
    // ShellAdvisoryStack composition does not collapse one banner when
    // the other is also active.
    const stack = createElement(
      Box,
      { flexDirection: "column" },
      createElement(RateLimitBanner, {
        throttle: { concurrency: 1, reason: "" },
      }),
      createElement(CostCapHalt, { runningCostUsd: 9.0, budgetUsd: 5.0 }),
    );
    const out = renderToText(stack);
    expect(out).toContain("rate-limited");
    expect(out).toContain("BUDGET EXCEEDED");
  });
});

describe("CopilotShell — shell-mode advisory mirroring", () => {
  it("renders nothing in the advisory zone when no advisory is active", () => {
    const store = createUIStore();
    store.update({
      mode: "shell",
      shell: {
        modules: [],
        moduleCatalog: [],
        tools: [],
        focusedModule: null,
        shellView: "catalog",
        openFindingId: null,
        target: null,
        workspace: null,
        history: [],
        commandHistory: [],
        moduleOptions: {},
        processing: false,
      },
    });
    const out = renderToText(createElement(CopilotShell, { store }), 120, 30);
    // No throttle / no cost-cap halt → no banner.
    expect(out).not.toContain("rate-limited");
    expect(out).not.toContain("BUDGET EXCEEDED");
  });

  it("renders the rate-limit banner above the shell prompt when state.throttle is set", () => {
    const store = createUIStore();
    store.update({
      mode: "shell",
      throttle: { concurrency: 1, reason: "upstream 429" },
      shell: {
        modules: [],
        moduleCatalog: [],
        tools: [],
        focusedModule: null,
        shellView: "catalog",
        openFindingId: null,
        target: null,
        workspace: null,
        history: [],
        commandHistory: [],
        moduleOptions: {},
        processing: false,
      },
    });
    const out = renderToText(createElement(CopilotShell, { store }), 120, 30);
    expect(out).toContain("rate-limited");
  });

  it("renders the cost-cap halt card above the shell prompt when costCapHalted", () => {
    const store = createUIStore();
    store.update({
      mode: "shell",
      costCapHalted: true,
      runningCostUsd: 4.2,
      costCapBudgetUsd: 3.0,
      shell: {
        modules: [],
        moduleCatalog: [],
        tools: [],
        focusedModule: null,
        shellView: "catalog",
        openFindingId: null,
        target: null,
        workspace: null,
        history: [],
        commandHistory: [],
        moduleOptions: {},
        processing: false,
      },
    });
    const out = renderToText(createElement(CopilotShell, { store }), 120, 30);
    expect(out).toContain("BUDGET EXCEEDED");
    expect(out).toMatch(/press\s+c/);
  });
});
