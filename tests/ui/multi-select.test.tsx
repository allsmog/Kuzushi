/**
 * MultiSelect tests — split between pure helpers (toggleSelection,
 * nextEnabledIndex, selectAllIds) and rendering snapshots.
 *
 * Interaction tests (useInput keystrokes) are deliberately skipped: the
 * existing UI test suite has no precedent for piping stdin into an Ink
 * render, and the pure helpers cover all the branchy logic. Layout/glyph
 * checks happen against rendered text with ANSI stripped.
 */

import { PassThrough, type Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import {
  MultiSelect,
  nextEnabledIndex,
  type SelectListItem,
  selectAllIds,
  toggleSelection,
} from "../../src/ui/primitives/MultiSelect.js";

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

const ITEMS: ReadonlyArray<SelectListItem<string>> = [
  { id: "sonnet", label: "Claude Sonnet", detail: "Anthropic" },
  { id: "opus", label: "Claude Opus", detail: "Anthropic" },
  { id: "haiku", label: "Claude Haiku", detail: "Anthropic", disabled: true },
  { id: "gpt5", label: "GPT-5", detail: "OpenAI" },
];

describe("toggleSelection", () => {
  it("adds a new id", () => {
    const next = toggleSelection(new Set(["a"]), "b");
    expect([...next].sort()).toEqual(["a", "b"]);
  });

  it("removes an existing id", () => {
    const next = toggleSelection(new Set(["a", "b"]), "a");
    expect([...next]).toEqual(["b"]);
  });

  it("does not mutate the input set", () => {
    const input = new Set(["a"]);
    toggleSelection(input, "b");
    expect([...input]).toEqual(["a"]);
  });

  it("toggling twice returns to the original membership", () => {
    const start = new Set(["a", "b"]);
    const once = toggleSelection(start, "c");
    const twice = toggleSelection(once, "c");
    expect([...twice].sort()).toEqual(["a", "b"]);
  });
});

describe("selectAllIds", () => {
  it("includes every enabled item", () => {
    const all = selectAllIds(ITEMS);
    expect(all.has("sonnet")).toBe(true);
    expect(all.has("opus")).toBe(true);
    expect(all.has("gpt5")).toBe(true);
  });

  it("excludes disabled items", () => {
    const all = selectAllIds(ITEMS);
    expect(all.has("haiku")).toBe(false);
  });

  it("returns empty set when every item is disabled", () => {
    const all = selectAllIds([
      { id: "x", label: "X", disabled: true },
      { id: "y", label: "Y", disabled: true },
    ]);
    expect(all.size).toBe(0);
  });
});

describe("nextEnabledIndex", () => {
  it("steps forward to the next enabled row", () => {
    expect(nextEnabledIndex(ITEMS, 0, 1)).toBe(1); // sonnet → opus
  });

  it("skips disabled rows", () => {
    expect(nextEnabledIndex(ITEMS, 1, 1)).toBe(3); // opus → (haiku skipped) → gpt5
  });

  it("wraps from the last enabled row to the first", () => {
    expect(nextEnabledIndex(ITEMS, 3, 1)).toBe(0); // gpt5 → sonnet
  });

  it("steps backward", () => {
    expect(nextEnabledIndex(ITEMS, 3, -1)).toBe(1); // gpt5 → (haiku skipped) → opus
  });

  it("wraps backward through the start", () => {
    expect(nextEnabledIndex(ITEMS, 0, -1)).toBe(3); // sonnet → gpt5
  });

  it("returns the same index when the list is empty", () => {
    expect(nextEnabledIndex([], 0, 1)).toBe(0);
  });

  it("returns the start index when every row is disabled", () => {
    const allDisabled: SelectListItem<string>[] = [
      { id: "x", label: "X", disabled: true },
      { id: "y", label: "Y", disabled: true },
    ];
    expect(nextEnabledIndex(allDisabled, 0, 1)).toBe(0);
  });
});

describe("<MultiSelect>", () => {
  function elt(overrides: Partial<Parameters<typeof MultiSelect>[0]> = {}): ReactElement {
    return createElement(MultiSelect, {
      items: ITEMS,
      selectedIds: new Set(),
      onToggle: () => {},
      onConfirm: () => {},
      ...overrides,
    });
  }

  it("renders a [ ] checkbox for every enabled row when nothing is selected", () => {
    const out = renderToText(elt());
    // Three enabled items get unchecked boxes.
    const matches = out.match(/\[ \]/g) ?? [];
    expect(matches.length).toBeGreaterThanOrEqual(3);
  });

  it("renders [✓] for selected items", () => {
    // Ink's debug-mode renderer can emit multiple frames before unmount; the
    // count is "at least one [✓] per selected id" rather than an exact match.
    const out = renderToText(elt({ selectedIds: new Set(["sonnet", "gpt5"]) }));
    const checked = out.match(/\[✓\]/g) ?? [];
    expect(checked.length).toBeGreaterThanOrEqual(2);
  });

  it("shows the position counter and selection count", () => {
    const out = renderToText(elt({ selectedIds: new Set(["sonnet"]) }));
    expect(out).toMatch(/\(1 of 4 · 1 selected\)/);
  });

  it("surfaces a hint when below minSelected", () => {
    const out = renderToText(elt({ selectedIds: new Set(), minSelected: 2 }));
    expect(out).toMatch(/pick ≥ 2 to continue/);
  });

  it("hides the below-min hint once the threshold is met", () => {
    const out = renderToText(elt({ selectedIds: new Set(["sonnet", "opus"]), minSelected: 2 }));
    expect(out).not.toMatch(/pick ≥/);
  });

  it("renders the emptyMessage when items is empty", () => {
    const out = renderToText(
      createElement(MultiSelect, {
        items: [],
        selectedIds: new Set(),
        onToggle: () => {},
        onConfirm: () => {},
        emptyMessage: "(no models configured)",
      }),
    );
    expect(out).toContain("(no models configured)");
  });

  it("includes each item's label in the rendered output", () => {
    const out = renderToText(elt());
    expect(out).toContain("Claude Sonnet");
    expect(out).toContain("Claude Opus");
    expect(out).toContain("GPT-5");
  });

  it("renders the detail field next to each row", () => {
    const out = renderToText(elt());
    // "Anthropic" appears at least three times across the three Anthropic rows.
    const anthropicMatches = out.match(/Anthropic/g) ?? [];
    expect(anthropicMatches.length).toBeGreaterThanOrEqual(3);
  });
});
