import { PassThrough, type Writable } from "node:stream";
import { render, Text } from "ink";
import { createElement, type ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DelayedBusyIndicator } from "../../src/ui/components/DelayedBusyIndicator.js";
import { InteractionErrorBoundary } from "../../src/ui/components/InteractionErrorBoundary.js";

// biome-ignore lint/suspicious/noControlCharactersInRegex: strip ANSI for stable assertions
const ANSI_RE = /\u001b(?:\[[0-9;?]*[ -/]*[@-~]|][^\u0007]*(?:\u0007|\u001b\\))/g;

function renderInk(node: ReactElement): {
  lastFrame: () => string;
  unmount: () => void;
} {
  const stream = new PassThrough();
  (stream as unknown as { columns: number; rows: number; isTTY: boolean }).columns = 100;
  (stream as unknown as { columns: number; rows: number; isTTY: boolean }).rows = 30;
  (stream as unknown as { columns: number; rows: number; isTTY: boolean }).isTTY = true;
  const chunks: Buffer[] = [];
  stream.on("data", (chunk: Buffer) => chunks.push(chunk));
  const instance = render(node, {
    stdout: stream as unknown as Writable & NodeJS.WriteStream,
    debug: true,
  });
  return {
    lastFrame: () => Buffer.concat(chunks).toString("utf-8").replace(ANSI_RE, ""),
    unmount: () => {
      instance.unmount();
      stream.end();
    },
  };
}

function ThrowingPanel(): ReactElement {
  throw new Error("render exploded");
}

describe("interaction feedback primitives", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps the busy indicator hidden before the 100ms threshold", () => {
    const t = renderInk(
      createElement(DelayedBusyIndicator, {
        label: "Working",
        detail: "Waiting for first progress event.",
      }),
    );

    expect(t.lastFrame()).not.toContain("Working");
    vi.advanceTimersByTime(99);
    expect(t.lastFrame()).not.toContain("Working");
    t.unmount();
  });

  it("shows spinner, elapsed time, detail, and cancel hint after the threshold", async () => {
    const t = renderInk(
      createElement(DelayedBusyIndicator, {
        label: "Working",
        detail: "Waiting for first progress event.",
      }),
    );

    await vi.advanceTimersByTimeAsync(100);
    expect(t.lastFrame()).toContain("Working");
    expect(t.lastFrame()).toContain("0ms");
    expect(t.lastFrame()).toContain("Waiting for first progress event.");
    expect(t.lastFrame()).toContain("Ctrl+C interrupt");
    t.unmount();
  });

  it("renders a graceful error card when a child panel throws during render", () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => void 0);
    const t = renderInk(
      createElement(
        InteractionErrorBoundary,
        { label: "Broken panel" },
        createElement(ThrowingPanel),
      ),
    );

    const out = t.lastFrame();
    expect(out).toContain("E_UI_RENDER");
    expect(out).toContain("Broken panel failed");
    expect(out).toContain("Next step:");
    expect(out).toContain("render exploded");
    t.unmount();
    consoleError.mockRestore();
  });

  it("passes children through when rendering succeeds", () => {
    const t = renderInk(
      createElement(
        InteractionErrorBoundary,
        { label: "Healthy panel" },
        createElement(Text, null, "render ok"),
      ),
    );

    expect(t.lastFrame()).toContain("render ok");
    t.unmount();
  });
});
