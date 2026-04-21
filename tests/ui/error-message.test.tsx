/**
 * Coverage for `classifyError` + `<ErrorMessage>` rendering.
 *
 * `classifyError` is a heuristic pattern-matcher — we exercise a
 * representative string per kind plus the generic fallback. For the
 * rendered component we check (a) the error text still reaches the
 * output and (b) the kind-specific hint follows. Exact ANSI isn't
 * asserted; we strip it before matching.
 */
import { PassThrough, type Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import {
  ErrorMessage,
  classifyError,
  type ErrorKind,
} from "../../src/ui/components/ErrorMessage.js";

// biome-ignore lint/suspicious/noControlCharactersInRegex: strips ANSI for stable assertions
const ANSI_RE = /\[[0-9;]*[a-zA-Z]/g;

function renderToText(node: ReactElement): string {
  const stream = new PassThrough();
  const chunks: Buffer[] = [];
  stream.on("data", (chunk: Buffer) => chunks.push(chunk));
  const instance = render(node, {
    stdout: stream as unknown as Writable & NodeJS.WriteStream,
    debug: true,
  });
  instance.unmount();
  stream.end();
  return Buffer.concat(chunks).toString("utf-8").replace(ANSI_RE, "").trimEnd();
}

describe("classifyError", () => {
  const cases: Array<[string, ErrorKind]> = [
    ["You are being rate limited", "rate-limit"],
    ["HTTP 429 Too Many Requests", "rate-limit"],
    ["Invalid API key", "auth"],
    ["401 Unauthorized", "auth"],
    ["403 Forbidden", "auth"],
    ["Request timed out after 30s", "timeout"],
    ["ETIMEDOUT at 10.0.0.1:443", "timeout"],
    ["Context window exceeded — prompt too long", "context-limit"],
    ["Aborted by SIGINT", "aborted"],
    ["user cancelled", "aborted"],
    ["ENOENT: no such file or directory", "generic"],
  ];

  for (const [input, expected] of cases) {
    it(`classifies "${input.slice(0, 40)}..." as ${expected}`, () => {
      expect(classifyError(input)).toBe(expected);
    });
  }
});

describe("<ErrorMessage>", () => {
  it("rate-limit renders headline + retry hint", () => {
    const out = renderToText(createElement(ErrorMessage, { text: "429 rate limited" }));
    expect(out).toContain("Rate limited");
    expect(out).toContain("429 rate limited");
    expect(out).toContain("Wait a moment");
    expect(out).toContain("/model");
  });

  it("auth renders headline + /auth hint", () => {
    const out = renderToText(createElement(ErrorMessage, { text: "Invalid API key" }));
    expect(out).toContain("Auth failure");
    expect(out).toContain("/auth");
  });

  it("timeout renders headline + API_TIMEOUT_MS hint", () => {
    const out = renderToText(createElement(ErrorMessage, { text: "ETIMEDOUT" }));
    expect(out).toContain("Timed out");
    expect(out).toContain("API_TIMEOUT_MS");
  });

  it("context-limit renders headline + /compact hint", () => {
    const out = renderToText(
      createElement(ErrorMessage, { text: "context window exceeded" }),
    );
    expect(out).toContain("Context limit reached");
    expect(out).toContain("/compact");
    expect(out).toContain("/clear");
  });

  it("aborted renders the text without the danger 'Error' headline", () => {
    const out = renderToText(
      createElement(ErrorMessage, { text: "Aborted by SIGINT" }),
    );
    expect(out).toContain("Aborted by SIGINT");
    // Aborted is operator-initiated — it shouldn't prefix with any
    // failure headline like "Auth failure" or "Rate limited".
    expect(out).not.toContain("failure");
    expect(out).not.toContain("Timed out");
  });

  it("generic renders the raw text", () => {
    const out = renderToText(
      createElement(ErrorMessage, { text: "Something unusual happened" }),
    );
    expect(out).toContain("Something unusual happened");
  });

  it("honors an explicit kind override", () => {
    // The text alone would classify as generic, but we force "rate-limit".
    const out = renderToText(
      createElement(ErrorMessage, {
        text: "provider quota exceeded",
        kind: "rate-limit",
      }),
    );
    expect(out).toContain("Rate limited");
    expect(out).toContain("Wait a moment");
  });
});
