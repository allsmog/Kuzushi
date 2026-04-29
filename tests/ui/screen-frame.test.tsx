import { Writable } from "node:stream";
import { render, Text } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { ScreenFrame } from "../../src/ui/primitives/ScreenFrame.js";
import { Table } from "../../src/ui/primitives/Table.js";

class CaptureStream extends Writable {
  columns: number;
  rows = 24;
  isTTY = true;
  private frames: string[] = [];

  constructor(columns = 80) {
    super();
    this.columns = columns;
  }

  _write(
    chunk: string | Uint8Array,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.frames.push(Buffer.from(chunk).toString("utf-8"));
    callback();
  }

  clearLine(): void {}
  clearScreenDown(): void {}
  cursorTo(): void {}
  moveCursor(): void {}
  getColumns(): number {
    return this.columns;
  }

  lastFrame(): string {
    for (let i = this.frames.length - 1; i >= 0; i--) {
      const frame = this.frames[i] ?? "";
      if (frame.replace(ANSI_RE, "").trim().length > 0) return frame;
    }
    return "";
  }
}

// biome-ignore lint/suspicious/noControlCharactersInRegex: strips ANSI for stable Ink assertions
const ANSI_RE = /\u001b(?:\[[0-9;?]*[ -/]*[@-~]|][^\u0007]*(?:\u0007|\u001b\\))/g;

function renderText(node: ReactElement, columns = 80): string {
  const stream = new CaptureStream(columns);
  const instance = render(node, {
    stdout: stream as unknown as Writable & NodeJS.WriteStream,
    debug: true,
  });
  instance.unmount();
  return stream.lastFrame().replace(ANSI_RE, "");
}

describe("ScreenFrame", () => {
  it("renders title, breadcrumbs, status, tabs, body, and footer chrome", () => {
    const out = renderText(
      createElement(
        ScreenFrame,
        {
          title: "findings",
          breadcrumbs: ["shell", "findings"],
          status: ["idle", "16 open"],
          tabs: [
            { id: "pipeline", label: "Pipeline", shortcut: "1" },
            { id: "findings", label: "Findings", shortcut: "2", active: true },
          ],
          footer: createElement(Text, null, "footer"),
        },
        createElement(Text, null, "body"),
      ),
    );
    expect(out).toContain("findings");
    expect(out).toContain("shell › findings");
    expect(out).toContain("idle · 16 open");
    expect(out).toContain("[2] Findings");
    expect(out).toContain("body");
    expect(out).toContain("footer");
  });
});

describe("Table selected row", () => {
  it("reserves a cursor gutter and marks the selected row", () => {
    const out = renderText(
      createElement(Table, {
        columns: [
          { key: "name", header: "NAME", width: 10 },
          { key: "state", header: "STATE", width: 8 },
        ],
        rows: [
          { name: "semgrep", state: "on" },
          { name: "codeql", state: "blocked" },
        ],
        showHeader: true,
        selectedIndex: 1,
        maxWidth: 30,
      }),
    );
    expect(out).toContain("  NAME");
    expect(out).toContain("❯ codeql");
    expect(out).toContain("  semgrep");
  });
});
