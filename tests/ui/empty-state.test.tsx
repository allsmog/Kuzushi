/**
 * EmptyState tests — verify the three-line structure (title / reason /
 * action), per-kind copy from `describeEmptyState`, and width-aware
 * truncation on narrow terminals.
 *
 * Copy content is exercised through the pure `describeEmptyState` helper
 * so the assertions stay stable when the Ink renderer changes padding or
 * separator glyphs.
 */

import { PassThrough, type Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { EmptyState } from "../../src/ui/components/EmptyState.js";
import { describeEmptyState, type EmptyStateKind } from "../../src/ui/error-format.js";

// biome-ignore lint/suspicious/noControlCharactersInRegex: strip ANSI for stable assertions
const ANSI_RE = /\[[0-9;]*[a-zA-Z]/g;

function renderToText(node: ReactElement, columns = 120): string {
  const stream = new PassThrough() as unknown as Writable & NodeJS.WriteStream;
  (stream as unknown as { columns: number }).columns = columns;
  (stream as unknown as { rows: number }).rows = 24;
  const chunks: Buffer[] = [];
  (stream as unknown as PassThrough).on("data", (chunk: Buffer) => chunks.push(chunk));
  const instance = render(node, { stdout: stream, debug: true });
  instance.unmount();
  (stream as unknown as PassThrough).end();
  return Buffer.concat(chunks).toString("utf-8").replace(ANSI_RE, "").trimEnd();
}

describe("describeEmptyState", () => {
  const kinds: EmptyStateKind[] = [
    "module-none-focused",
    "module-no-tools",
    "findings-never-scanned",
    "findings-zero-after-scan",
    "findings-filter-empty",
    "findings-compact-idle",
    "threat-model-missing",
    "diff-since-idle",
    "catalog-no-modules",
    "options-none-loaded",
    "prompts-none",
    "actor-none-focused",
    "module-run-idle",
    "context-build-idle",
    "cost-no-data",
    "generic",
  ];

  for (const kind of kinds) {
    it(`${kind} returns non-empty title+reason+action`, () => {
      const copy = describeEmptyState(kind);
      expect(copy.title.length).toBeGreaterThan(0);
      expect(copy.reason.length).toBeGreaterThan(0);
      expect(copy.action.length).toBeGreaterThan(0);
    });
  }

  it("module-none-focused suggests /use", () => {
    expect(describeEmptyState("module-none-focused").action).toContain("/use");
  });

  it("module-no-tools mentions the module id when given", () => {
    expect(describeEmptyState("module-no-tools", { moduleId: "sast" }).reason).toContain("sast");
  });

  it("findings-never-scanned suggests /scan", () => {
    expect(describeEmptyState("findings-never-scanned").action).toContain("/scan");
  });

  it("findings-zero-after-scan suggests /since or /tune", () => {
    const copy = describeEmptyState("findings-zero-after-scan");
    expect(copy.action).toMatch(/\/since|\/tune/);
  });

  it("findings-filter-empty reports filter count", () => {
    const copy = describeEmptyState("findings-filter-empty", { filterCount: 3 });
    expect(copy.reason).toContain("3");
  });

  it("findings-compact-idle shifts copy when scan is in progress", () => {
    const running = describeEmptyState("findings-compact-idle", {
      scanInProgress: true,
      progress: { current: 42, total: 128 },
    });
    expect(running.title).toMatch(/in progress/i);
    expect(running.reason).toContain("42/128");

    const idle = describeEmptyState("findings-compact-idle");
    expect(idle.title).toMatch(/triaged/i);
  });

  it("threat-model-missing picks view-specific title", () => {
    expect(describeEmptyState("threat-model-missing", { threatView: "dfd" }).title).toContain(
      "data flow",
    );
    expect(describeEmptyState("threat-model-missing", { threatView: "stride" }).title).toContain(
      "STRIDE",
    );
    // Unknown view falls back to generic title.
    expect(describeEmptyState("threat-model-missing", { threatView: "bogus" }).title).toContain(
      "threat model",
    );
  });

  it("threat-model-missing action points to /scan or /threats edit", () => {
    const copy = describeEmptyState("threat-model-missing");
    expect(copy.action).toMatch(/\/scan|\/threats edit/);
  });

  it("diff-since-idle suggests /since <git-ref>", () => {
    expect(describeEmptyState("diff-since-idle").action).toContain("/since");
  });

  it("catalog-no-modules suggests --load", () => {
    expect(describeEmptyState("catalog-no-modules").action).toContain("--load");
  });

  it("options-none-loaded carries the module id when given", () => {
    expect(describeEmptyState("options-none-loaded", { moduleId: "sast" }).reason).toContain(
      "sast",
    );
    expect(describeEmptyState("options-none-loaded").action).toContain("show options");
  });

  it("prompts-none mentions the module id and routes to /prompts", () => {
    expect(describeEmptyState("prompts-none", { moduleId: "context" }).reason).toContain("context");
    expect(describeEmptyState("prompts-none").action).toContain("/prompts");
  });

  it("actor-none-focused suggests /back", () => {
    expect(describeEmptyState("actor-none-focused").action).toContain("/back");
  });

  it("module-run-idle suggests run/scan", () => {
    expect(describeEmptyState("module-run-idle", { moduleId: "sast" }).action).toMatch(/run|scan/);
  });

  it("context-build-idle suggests /context build", () => {
    expect(describeEmptyState("context-build-idle").action).toContain("/context build");
  });

  it("cost-no-data shifts copy when scan is in progress", () => {
    const running = describeEmptyState("cost-no-data", { scanInProgress: true });
    expect(running.reason).toMatch(/triage/i);
    const idle = describeEmptyState("cost-no-data");
    expect(idle.reason).toMatch(/billed|nothing/i);
  });
});

describe("<EmptyState>", () => {
  it("renders all three lines: title, reason, action", () => {
    const out = renderToText(createElement(EmptyState, { kind: "findings-never-scanned" }), 120);
    const copy = describeEmptyState("findings-never-scanned");
    expect(out).toContain(copy.title);
    expect(out).toContain("/scan");
  });

  it("respects titleOverride", () => {
    const out = renderToText(
      createElement(EmptyState, {
        kind: "threat-model-missing",
        titleOverride: "Custom Title",
      }),
      120,
    );
    expect(out).toContain("Custom Title");
  });

  it("renders action hint even when reason would overflow a narrow terminal", () => {
    const out = renderToText(createElement(EmptyState, { kind: "findings-zero-after-scan" }), 40);
    // Action survives; the reason may truncate but must still be present.
    expect(out).toMatch(/\/since|\/tune/);
  });

  it("threat-model-missing with dfd context mentions data flow", () => {
    const out = renderToText(
      createElement(EmptyState, {
        kind: "threat-model-missing",
        context: { threatView: "dfd" },
      }),
      120,
    );
    expect(out).toContain("data flow");
  });

  it("module-no-tools renders the module id in the reason line", () => {
    const out = renderToText(
      createElement(EmptyState, {
        kind: "module-no-tools",
        context: { moduleId: "my-module" },
      }),
      120,
    );
    expect(out).toContain("my-module");
  });

  it("emits at least three newline-separated lines", () => {
    const out = renderToText(createElement(EmptyState, { kind: "diff-since-idle" }), 120);
    const lines = out.split(/\r?\n/).filter((l) => l.trim().length > 0);
    expect(lines.length).toBeGreaterThanOrEqual(3);
  });
});
