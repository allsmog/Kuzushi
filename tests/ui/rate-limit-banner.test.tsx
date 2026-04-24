/**
 * RateLimitBanner tests — verify the actionable copy: concrete config
 * recovery hint, "retrying …" suffix when `until` is supplied, and auto-hide
 * when no throttle is active.
 */

import { PassThrough, type Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { formatUntil, RateLimitBanner } from "../../src/ui/components/RateLimitBanner.js";

// biome-ignore lint/suspicious/noControlCharactersInRegex: strip ANSI for assertions
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

describe("RateLimitBanner", () => {
  it("returns null when throttle is unset", () => {
    const out = renderToText(createElement(RateLimitBanner, { throttle: undefined }));
    expect(out.trim()).toBe("");
  });

  it("returns null when throttle is null", () => {
    const out = renderToText(createElement(RateLimitBanner, { throttle: null }));
    expect(out.trim()).toBe("");
  });

  it("renders concurrency and a /config advanced recovery hint", () => {
    const out = renderToText(
      createElement(RateLimitBanner, {
        throttle: { concurrency: 4, reason: "429 from provider" },
      }),
    );
    expect(out).toContain("rate-limited");
    expect(out).toContain("concurrency reduced to 4");
    expect(out).toContain("triageConcurrency");
    expect(out).toContain("/config advanced");
  });

  it("does not suggest the removed /concurrency shortcut", () => {
    const out = renderToText(
      createElement(RateLimitBanner, {
        throttle: { concurrency: 8, reason: "" },
      }),
    );
    expect(out).not.toContain("/concurrency");
  });

  it("keeps the config hint at minimum concurrency", () => {
    const out = renderToText(
      createElement(RateLimitBanner, {
        throttle: { concurrency: 1, reason: "" },
      }),
    );
    expect(out).toContain("/config advanced");
    expect(out).not.toContain("/concurrency 0");
  });

  it("renders retry-after when `until` is in the near future", () => {
    const fixedNow = 1_000_000;
    const out = renderToText(
      createElement(RateLimitBanner, {
        throttle: { concurrency: 2, reason: "", until: fixedNow + 45_000 },
        now: () => fixedNow,
      }),
    );
    expect(out).toContain("retrying in");
    expect(out).toMatch(/retrying in \d+s/);
  });

  it("renders the reason line when provided", () => {
    const out = renderToText(
      createElement(RateLimitBanner, {
        throttle: { concurrency: 2, reason: "upstream 429" },
      }),
    );
    expect(out).toContain("upstream 429");
  });

  it("omits retry-after when `until` is in the past", () => {
    const fixedNow = 1_000_000;
    const out = renderToText(
      createElement(RateLimitBanner, {
        throttle: { concurrency: 2, reason: "", until: fixedNow - 1_000 },
        now: () => fixedNow,
      }),
    );
    expect(out).not.toContain("retrying");
  });
});

describe("formatUntil", () => {
  it("returns empty for undefined or past", () => {
    expect(formatUntil(undefined, 1_000)).toBe("");
    expect(formatUntil(0, 1_000)).toBe("");
    expect(formatUntil(500, 1_000)).toBe("");
  });
  it("returns seconds when near future (<120s)", () => {
    expect(formatUntil(1_000 + 30_000, 1_000)).toBe("in 30s");
  });
  it("returns minutes for 2-60 minute window", () => {
    expect(formatUntil(1_000 + 300_000, 1_000)).toBe("in 5m");
  });
  it("returns wall-clock HH:MM for long throttles", () => {
    const long = new Date(2026, 0, 1, 14, 20).getTime();
    const now = long - 5 * 3600 * 1000;
    expect(formatUntil(long, now)).toMatch(/^at \d{2}:\d{2}$/);
  });
});
