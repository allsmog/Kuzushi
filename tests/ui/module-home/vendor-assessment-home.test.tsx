import { Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { createManualUiClock, UiClockProvider } from "../../../src/ui/clock.js";
import { VendorAssessmentHome } from "../../../src/ui/components/module-home/vendor-assessment-home.js";
import type { ShellState } from "../../../src/ui/state.js";

class FrameCaptureStream extends Writable {
  columns = 100;
  rows = 24;
  isTTY = true;
  private frames: string[] = [];
  _write(chunk: string | Uint8Array, _e: BufferEncoding, cb: (e?: Error | null) => void): void {
    this.frames.push(Buffer.from(chunk).toString("utf-8"));
    cb();
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
      if (stripAnsi(frame).trim().length > 0) return frame;
    }
    return "";
  }
}

const ANSI_RE = new RegExp(`${String.fromCharCode(0x1b)}\\[[^A-Za-z]*[A-Za-z]`, "g");
function stripAnsi(s: string): string {
  return s.replace(ANSI_RE, "");
}

function renderText(node: ReactElement): string {
  const stream = new FrameCaptureStream();
  const clock = createManualUiClock(0);
  const instance = render(createElement(UiClockProvider, { clock }, node), {
    stdout: stream as unknown as Writable & NodeJS.WriteStream,
    debug: true,
  });
  instance.unmount();
  return stripAnsi(stream.lastFrame())
    .replace(/^(?:\r?\n)+/, "")
    .trimEnd();
}

function shell(overrides: Partial<ShellState> = {}): ShellState {
  return {
    modules: [],
    moduleCatalog: [],
    tools: [],
    focusedModule: "vendor-assessment",
    shellView: "module",
    openFindingId: null,
    target: "/repo",
    workspace: "demo-workspace",
    history: [],
    commandHistory: [],
    moduleOptions: {},
    processing: false,
    ...overrides,
  };
}

describe("VendorAssessmentHome", () => {
  it("renders empty draft scope actions", () => {
    const out = renderText(createElement(VendorAssessmentHome, { shell: shell() }));
    expect(out).toContain("kuzushi/vendor-assessment");
    expect(out).toContain("confidence");
    expect(out).toContain("empty");
    expect(out).toContain("attach <path-or-url>");
    expect(out).toContain("clear scope");
  });

  it("renders document-backed draft scope", () => {
    const out = renderText(
      createElement(VendorAssessmentHome, {
        shell: shell({
          vendorAssessment: {
            profile: "enterprise-ai",
            vendorName: "Vendor One",
            confidence: "document-backed",
            missingArtifacts: ["architecture diagram"],
            documents: [
              {
                title: "questionnaire.md",
                kind: "questionnaire",
                status: "parsed",
                detail: "128 chars",
              },
            ],
          },
        }),
      }),
    );
    expect(out).toContain("Vendor One");
    expect(out).toContain("document-backed");
    expect(out).toContain("questionnaire.md");
    expect(out).toContain("architecture diagram");
  });
});
