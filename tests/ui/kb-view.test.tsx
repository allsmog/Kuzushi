/**
 * KbView + AttachmentsBlock — render snapshots covering empty and populated
 * states. Asserts that the visible text contains the expected status glyphs,
 * titles, kind labels, and the "use `attach <path>`" hint when empty.
 */

import { PassThrough, type Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import type { AttachmentsHomeSlice } from "../../src/modules/_shared/attachments/index.js";
import { KbView } from "../../src/ui/components/KbView.js";
import { AttachmentsBlock } from "../../src/ui/components/module-home/AttachmentsBlock.js";
import type { ShellState } from "../../src/ui/state.js";

// Match real ANSI escape sequences (ESC `` + `[…m`) so literal `[x]`
// status glyphs in the rendered text aren't accidentally stripped.
// biome-ignore lint/suspicious/noControlCharactersInRegex: strip ANSI for stable assertions
const ANSI_RE = /\u001b\[[0-9;]*[a-zA-Z]/g;

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

function makeSlice(documents: AttachmentsHomeSlice["documents"] = []): AttachmentsHomeSlice {
  return {
    moduleId: "threat-model",
    scopePath: "/tmp/x/.kuzushi/threat-model/attachments.json",
    documents,
    totals: {
      total: documents.length,
      parsed: documents.filter((d) => d.status === "parsed").length,
      needsReview: documents.filter((d) => d.status === "needs-human-review").length,
      metadata: documents.filter((d) => d.status === "metadata-only").length,
      error: documents.filter((d) => d.status === "error").length,
    },
  };
}

const SAMPLE_DOCS: AttachmentsHomeSlice["documents"] = [
  {
    id: "abc123",
    title: "rfc-0042-checkout.md",
    kind: "design-doc",
    kindLabel: "design-doc",
    status: "parsed",
    sourceType: "local",
    source: "/tmp/x/docs/rfc-0042-checkout.md",
    sizeBytes: 12480,
    charCount: 12480,
    attachedAt: "2026-04-26T00:00:00.000Z",
    detail: "12.4k chars · 1d ago",
    parseWarnings: [],
  },
  {
    id: "def456",
    title: "arch-diagram.png",
    kind: "diagram",
    kindLabel: "diagram",
    status: "needs-human-review",
    sourceType: "local",
    source: "/tmp/x/docs/arch-diagram.png",
    sizeBytes: 88000,
    attachedAt: "2026-04-26T00:00:00.000Z",
    detail: "needs review · 1d ago",
    parseWarnings: ["Image or diagram file retained in scope; human review required."],
  },
  {
    id: "789xyz",
    title: "wiki/runbook (404)",
    kind: "runbook",
    kindLabel: "runbook",
    status: "error",
    sourceType: "url",
    source: "https://wiki.internal/runbook",
    attachedAt: "2026-04-27T00:00:00.000Z",
    detail: "fetch failed",
    parseWarnings: ["URL fetching is not configured for this module yet"],
  },
];

describe("AttachmentsBlock", () => {
  it("renders the empty placeholder when no slice is provided", () => {
    const out = renderToText(
      createElement(AttachmentsBlock, { slice: null, moduleId: "threat-model" }),
    );
    expect(out).toContain("attachments");
    expect(out).toContain("(none attached)");
    expect(out).toContain("attach <path-or-url>");
  });

  it("renders the documents table with status glyphs and kind labels", () => {
    const slice = makeSlice(SAMPLE_DOCS);
    const out = renderToText(createElement(AttachmentsBlock, { slice, moduleId: "threat-model" }));
    expect(out).toContain("3 attached");
    expect(out).toContain("rfc-0042-checkout.md");
    expect(out).toContain("design-doc");
    expect(out).toContain("[x]"); // parsed
    expect(out).toContain("[ ]"); // needs review
    expect(out).toContain("[!]"); // error
    expect(out).toContain("attach <path-or-url>");
  });

  it("hides the actions row when showActions=false", () => {
    const slice = makeSlice(SAMPLE_DOCS);
    const out = renderToText(
      createElement(AttachmentsBlock, {
        slice,
        moduleId: "threat-model",
        showActions: false,
      }),
    );
    expect(out).not.toContain("attach <path-or-url>");
    expect(out).toContain("rfc-0042-checkout.md");
  });

  it("renders the per-status totals breakdown in the header", () => {
    const slice = makeSlice(SAMPLE_DOCS);
    const out = renderToText(createElement(AttachmentsBlock, { slice, moduleId: "threat-model" }));
    expect(out).toMatch(/3 attached.*1 parsed.*1 review.*1 error/);
  });
});

describe("KbView", () => {
  function shellWith(slice: AttachmentsHomeSlice | null, cursor = 0): ShellState {
    return {
      modules: ["threat-model"],
      tools: [],
      focusedModule: "threat-model",
      shellView: "kb",
      openFindingId: null,
      target: null,
      workspace: null,
      processing: false,
      history: [],
      commandHistory: [],
      moduleOptions: {},
      kb: { moduleId: "threat-model", cursor, collapsed: false },
      kbState: slice ? { "threat-model": slice } : {},
    } as ShellState;
  }

  it("shows the empty-state hint with sample attach commands when no docs are staged", () => {
    const out = renderToText(createElement(KbView, { shell: shellWith(null) }));
    expect(out).toContain("kb");
    expect(out).toContain("(no attachments yet)");
    expect(out).toContain("attach ./docs/architecture.md");
    expect(out).toContain("attach https://example.com/runbook");
  });

  it("renders the list pane with the cursor pointing to the selected row", () => {
    const slice = makeSlice(SAMPLE_DOCS);
    const out = renderToText(createElement(KbView, { shell: shellWith(slice, 1) }));
    expect(out).toContain("rfc-0042-checkout.md");
    expect(out).toContain("arch-diagram.png");
    // The selected row gets the ▶ indicator. The cursor=1 means row 2.
    const lines = out.split(/\r?\n/);
    const selected = lines.find((l) => l.includes("▶"));
    expect(selected).toBeDefined();
    expect(selected).toContain("arch-diagram.png");
  });

  it("renders the preview pane with source/status/warnings for the selected doc", () => {
    const slice = makeSlice(SAMPLE_DOCS);
    const out = renderToText(createElement(KbView, { shell: shellWith(slice, 1) }));
    expect(out).toContain("preview");
    expect(out).toContain("/tmp/x/docs/arch-diagram.png");
    expect(out).toContain("needs-human-review");
    expect(out).toContain("Image or diagram file retained in scope");
  });

  it("clamps the cursor when it points past the last row", () => {
    const slice = makeSlice(SAMPLE_DOCS);
    const out = renderToText(createElement(KbView, { shell: shellWith(slice, 99) }));
    // Last row is the runbook (404)
    const lines = out.split(/\r?\n/);
    const selected = lines.find((l) => l.includes("▶"));
    expect(selected).toContain("wiki/runbook");
  });
});
