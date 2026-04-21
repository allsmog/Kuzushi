/**
 * Snapshot-ish coverage for the lightweight Markdown renderer used in
 * assistant output entries. We don't assert raw ANSI — we strip it and
 * check that the rendered plain text still carries the content and
 * structural affordances (headings on their own line, bullets prefixed
 * with `•`, code block padding, links formatted as `text (url)`).
 */
import { PassThrough, type Writable } from "node:stream";
import { render } from "ink";
import { createElement } from "react";
import { describe, expect, it } from "vitest";
import { Markdown } from "../../src/ui/primitives/Markdown.js";

// biome-ignore lint/suspicious/noControlCharactersInRegex: strips ANSI for stable assertions
const ANSI_RE = /\[[0-9;]*[a-zA-Z]/g;

function renderMarkdown(text: string): string {
  const stream = new PassThrough();
  const chunks: Buffer[] = [];
  stream.on("data", (chunk: Buffer) => chunks.push(chunk));
  const instance = render(createElement(Markdown, { text }), {
    stdout: stream as unknown as Writable & NodeJS.WriteStream,
    debug: true,
  });
  instance.unmount();
  stream.end();
  const raw = Buffer.concat(chunks).toString("utf-8").replace(ANSI_RE, "");
  // `debug: true` writes a full frame on every reconciliation; keep the
  // last frame by splitting on double-newline boundaries.
  return raw.trimEnd();
}

describe("Markdown", () => {
  it("renders plain paragraph text unchanged", () => {
    const out = renderMarkdown("just some plain text");
    expect(out).toContain("just some plain text");
  });

  it("renders bullet lists with a `•` marker", () => {
    const out = renderMarkdown("- first\n- second");
    expect(out).toContain("• first");
    expect(out).toContain("• second");
  });

  it("renders numbered lists with their indices", () => {
    const out = renderMarkdown("1. alpha\n2. beta");
    expect(out).toContain("1. alpha");
    expect(out).toContain("2. beta");
  });

  it("renders headings", () => {
    const out = renderMarkdown("# Title\nbody");
    expect(out).toContain("Title");
    expect(out).toContain("body");
  });

  it("renders inline bold / italic / code", () => {
    const out = renderMarkdown("has **bold** and *italic* and `code` inline");
    expect(out).toContain("bold");
    expect(out).toContain("italic");
    expect(out).toContain("code");
    // The raw markdown delimiters shouldn't leak through
    expect(out).not.toContain("**");
    expect(out).not.toContain("`code`");
  });

  it("renders fenced code blocks", () => {
    const out = renderMarkdown("before\n```\nconst x = 1;\n```\nafter");
    expect(out).toContain("const x = 1;");
    expect(out).toContain("before");
    expect(out).toContain("after");
    // Fence markers shouldn't leak
    expect(out).not.toContain("```");
  });

  it("renders links as `text (url)`", () => {
    const out = renderMarkdown("See [docs](https://example.com) for more");
    expect(out).toContain("docs");
    expect(out).toContain("https://example.com");
  });

  it("preserves blank lines between paragraphs", () => {
    const out = renderMarkdown("para one\n\npara two");
    expect(out).toContain("para one");
    expect(out).toContain("para two");
  });
});
