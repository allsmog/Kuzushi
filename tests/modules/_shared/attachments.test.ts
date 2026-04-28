/**
 * Shared attachment subsystem — storage, parser, prompt rendering, and the
 * tool factory contract. Per-module integration tests live alongside each
 * consuming module so this file stays focused on the generic behaviour.
 */

import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  type AttachmentDocument,
  attachDocument,
  buildHomeSlice,
  createAttachmentTools,
  defaultAttachmentAdapter,
  inferKind,
  type KindSpec,
  removeAttachment,
  renderUntrustedAttachments,
  upsertAttachment,
} from "../../../src/modules/_shared/attachments/index.js";
import { createMockToolContext } from "../../../src/testing/index.js";

const tempDirs: string[] = [];

function tempRoot(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "shared-attachments-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

type TestKind = "design-doc" | "diagram" | "runbook" | "other";

const TEST_SPEC: KindSpec<TestKind> = {
  moduleId: "test-module",
  default: "other",
  kinds: ["design-doc", "diagram", "runbook", "other"],
  inference: [
    { kind: "diagram", pattern: /\b(diagram|dfd|architecture)\b/ },
    { kind: "runbook", pattern: /\b(runbook|playbook)\b/ },
    { kind: "design-doc", pattern: /\b(rfc|design|adr)\b/ },
  ],
  label: (k) => k,
};

describe("inferKind", () => {
  it("returns the explicit override when it matches the spec's enum", () => {
    expect(inferKind("anything.md", "diagram", TEST_SPEC)).toBe("diagram");
  });

  it("ignores unknown overrides and falls back to filename inference", () => {
    expect(inferKind("architecture.png", "bogus-kind", TEST_SPEC)).toBe("diagram");
  });

  it("falls back to spec.default when nothing matches", () => {
    expect(inferKind("randomfile.bin", undefined, TEST_SPEC)).toBe("other");
  });

  it("matches first-rule-wins, not last", () => {
    // "rfc-architecture.md" matches both diagram (architecture) and design-doc (rfc).
    // Spec lists diagram first, so it should win.
    expect(inferKind("rfc-architecture.md", undefined, TEST_SPEC)).toBe("diagram");
  });
});

describe("attachDocument", () => {
  it("parses .md files with status=parsed and the text parser", () => {
    const root = tempRoot();
    const file = path.join(root, "design.md");
    writeFileSync(file, "# Design\nThis service is multi-tenant.\n");

    const doc = attachDocument({ source: file, cwd: root }, TEST_SPEC);

    expect(doc.kind).toBe("design-doc");
    expect(doc.status).toBe("parsed");
    expect(doc.extracted?.parser).toBe("text");
    expect(doc.extracted?.text).toContain("multi-tenant");
    expect(doc.parseWarnings).toEqual([]);
  });

  it("marks images needs-human-review with no extracted text", () => {
    const root = tempRoot();
    const file = path.join(root, "architecture.png");
    writeFileSync(file, "fake png");

    const doc = attachDocument({ source: file, cwd: root }, TEST_SPEC);

    expect(doc.kind).toBe("diagram");
    expect(doc.status).toBe("needs-human-review");
    expect(doc.extracted).toBeUndefined();
    expect(doc.parseWarnings.join(" ")).toContain("Image");
  });

  it("marks unknown extensions metadata-only", () => {
    const root = tempRoot();
    const file = path.join(root, "something.bin");
    writeFileSync(file, "binary");

    const doc = attachDocument({ source: file, cwd: root }, TEST_SPEC);

    expect(doc.status).toBe("metadata-only");
    expect(doc.parseWarnings.join(" ")).toContain("Unsupported file extension");
  });

  it("refuses files larger than maxBytes with status=error", () => {
    const root = tempRoot();
    const file = path.join(root, "big.md");
    writeFileSync(file, "x".repeat(2048));

    const doc = attachDocument({ source: file, cwd: root }, TEST_SPEC, { maxBytes: 1024 });

    expect(doc.status).toBe("error");
    expect(doc.parseWarnings.join(" ")).toContain("attachment cap");
    expect(doc.extracted).toBeUndefined();
  });

  it("returns error status for missing local files", () => {
    const root = tempRoot();
    const doc = attachDocument({ source: path.join(root, "missing.md"), cwd: root }, TEST_SPEC);
    expect(doc.status).toBe("error");
    expect(doc.parseWarnings.join(" ")).toContain("does not exist");
  });

  it("treats URLs as metadata-only without fetching", () => {
    const doc = attachDocument(
      { source: "https://example.com/runbook", cwd: process.cwd() },
      TEST_SPEC,
    );
    expect(doc.sourceType).toBe("url");
    expect(doc.kind).toBe("runbook");
    expect(doc.status).toBe("metadata-only");
    expect(doc.parseWarnings.join(" ")).toContain("URL fetching is not configured");
  });

  it("metadataOnly=true skips parsing even for parseable extensions", () => {
    const root = tempRoot();
    const file = path.join(root, "design.md");
    writeFileSync(file, "# Design");

    const doc = attachDocument({ source: file, cwd: root, metadataOnly: true }, TEST_SPEC);

    expect(doc.status).toBe("metadata-only");
    expect(doc.extracted).toBeUndefined();
    expect(doc.parseWarnings.join(" ")).toContain("metadataOnly=true");
  });
});

describe("renderUntrustedAttachments", () => {
  function fakeDoc(
    text: string,
    overrides: Partial<AttachmentDocument<TestKind>> = {},
  ): AttachmentDocument<TestKind> {
    return {
      id: overrides.id ?? "abc123",
      source: overrides.source ?? "/tmp/whatever.md",
      sourceType: "local",
      kind: "design-doc",
      title: overrides.title ?? "whatever.md",
      status: "parsed",
      extracted: { text, charCount: text.length, parser: "text" },
      parseWarnings: [],
      attachedAt: "2026-04-27T00:00:00.000Z",
      ...overrides,
    };
  }

  it("wraps documents in nonce-protected delimiters with the moduleId attribute", () => {
    const docs = [fakeDoc("system architecture overview")];
    const { block, nonce } = renderUntrustedAttachments(docs, { moduleId: "threat-model" });

    expect(nonce).toMatch(/^[0-9a-f]{8,16}$/);
    expect(block).toContain(`<untrusted_attachment moduleId="threat-model" nonce="${nonce}">`);
    expect(block).toContain(`</untrusted_attachment moduleId="threat-model" nonce="${nonce}">`);
    expect(block).toContain("system architecture overview");
    expect(block).toContain("ATTACHMENT 1 OF 1: whatever.md");
  });

  it("emits the empty placeholder when no documents are attached", () => {
    const { block } = renderUntrustedAttachments([], {
      moduleId: "x",
      emptyPlaceholder: "(none staged)",
    });
    expect(block).toBe("(none staged)");
  });

  it("uses the default placeholder for empty docs when none is supplied", () => {
    const { block } = renderUntrustedAttachments([], { moduleId: "x" });
    expect(block).toBe("(no reference material attached)");
  });

  it("substitutes a placeholder when extracted text is missing", () => {
    const docs = [
      fakeDoc("", {
        status: "needs-human-review",
        parseWarnings: ["Image file"],
        extracted: undefined,
      }),
    ];
    const { block } = renderUntrustedAttachments(docs, { moduleId: "x" });
    expect(block).toContain("[No extractable text. Status: needs-human-review.");
    expect(block).toContain("Image file");
  });

  it("respects an explicit nonce so callers can stabilise tests", () => {
    const docs = [fakeDoc("body text")];
    const { block, nonce } = renderUntrustedAttachments(docs, {
      moduleId: "x",
      nonce: "deadbeef",
    });
    expect(nonce).toBe("deadbeef");
    expect(block).toContain('nonce="deadbeef"');
  });
});

describe("storage adapter", () => {
  it("default adapter round-trips through .kuzushi/<id>/attachments.json", () => {
    const root = tempRoot();
    const adapter = defaultAttachmentAdapter<TestKind>("test-module");
    const file = path.join(root, ".kuzushi/test-module/attachments.json");

    expect(adapter.read(root)).toEqual([]);
    expect(existsSync(file)).toBe(false);

    const doc: AttachmentDocument<TestKind> = {
      id: "abc123",
      source: "/tmp/x.md",
      sourceType: "local",
      kind: "design-doc",
      title: "x.md",
      status: "parsed",
      parseWarnings: [],
      attachedAt: "2026-04-27T00:00:00.000Z",
    };
    adapter.write(root, [doc]);
    expect(existsSync(file)).toBe(true);
    expect(adapter.read(root)).toEqual([doc]);

    adapter.clear(root);
    expect(existsSync(file)).toBe(false);
  });

  it("upsertAttachment dedups by id and replaces in place", () => {
    const a: AttachmentDocument<TestKind> = mkDoc("a", "v1");
    const b: AttachmentDocument<TestKind> = mkDoc("b", "v1");
    const aV2: AttachmentDocument<TestKind> = mkDoc("a", "v2");
    const docs = upsertAttachment(upsertAttachment([a], b), aV2);
    expect(docs).toHaveLength(2);
    expect(docs.find((d) => d.id === "a")?.title).toBe("v2");
  });

  it("removeAttachment matches by exact id, unique prefix, or unique title", () => {
    const a = mkDoc("abcd1234ef00", "alpha.md");
    const b = mkDoc("abff0099aa00", "beta.md");
    const c = mkDoc("ddddeeeeffff", "gamma.md");
    const docs = [a, b, c];

    expect(removeAttachment(docs, "abcd1234ef00").removed?.id).toBe("abcd1234ef00");
    expect(removeAttachment(docs, "ddddeeee").removed?.id).toBe("ddddeeeeffff");
    const titleHit = removeAttachment(docs, "alpha.md");
    expect(titleHit.removed?.id).toBe("abcd1234ef00");
  });

  it("removeAttachment returns ambiguous when a prefix matches multiple ids", () => {
    const a = mkDoc("abcd1234ef00", "alpha.md");
    const b = mkDoc("abff0099aa00", "beta.md");
    const result = removeAttachment([a, b], "ab");
    expect(result.ambiguous).toBe(true);
    expect(result.removed).toBeNull();
    if (result.ambiguous) {
      expect(result.matches).toHaveLength(2);
    }
  });

  it("returns an empty array when the JSON file is corrupt", () => {
    const root = tempRoot();
    const adapter = defaultAttachmentAdapter<TestKind>("test-module");
    const file = path.join(root, ".kuzushi/test-module/attachments.json");
    adapter.write(root, []);
    writeFileSync(file, "{ this is not json");
    expect(adapter.read(root)).toEqual([]);
  });
});

describe("buildHomeSlice", () => {
  it("computes per-status totals", () => {
    const docs: AttachmentDocument<TestKind>[] = [
      mkDoc("a", "alpha.md", "parsed"),
      mkDoc("b", "beta.png", "needs-human-review"),
      mkDoc("c", "gamma.bin", "metadata-only"),
      mkDoc("d", "delta.zip", "error"),
    ];
    const slice = buildHomeSlice("test-module", "/tmp/scope.json", docs, TEST_SPEC, Date.now());
    expect(slice.totals).toEqual({ total: 4, parsed: 1, needsReview: 1, metadata: 1, error: 1 });
    expect(slice.documents).toHaveLength(4);
    expect(slice.documents[0]?.kindLabel).toBe("design-doc");
    expect(slice.scopePath).toBe("/tmp/scope.json");
  });
});

describe("createAttachmentTools", () => {
  it("rejects a moduleId/spec mismatch at construction time", () => {
    expect(() => createAttachmentTools("other-id", TEST_SPEC)).toThrow(/does not match KindSpec/);
  });

  it("emits exactly four tools with the expected names", () => {
    const tools = createAttachmentTools("test-module", TEST_SPEC);
    expect(tools.map((t) => t.name).sort()).toEqual([
      "test-module:attach",
      "test-module:attachments",
      "test-module:detach",
      "test-module:reparse",
    ]);
  });

  it("attach → list → detach round-trip persists through the default adapter", async () => {
    const root = tempRoot();
    const file = path.join(root, "design.md");
    writeFileSync(file, "design content body that is long enough to be parsed");
    const ctx = createMockToolContext({ cwd: root, target: root });

    const tools = createAttachmentTools("test-module", TEST_SPEC);
    const attach = tools.find((t) => t.name === "test-module:attach")!;
    const list = tools.find((t) => t.name === "test-module:attachments")!;
    const detach = tools.find((t) => t.name === "test-module:detach")!;

    const attachResult = await attach.execute({ source: file }, ctx);
    expect(attachResult.ok).toBe(true);
    const listResult = await list.execute({}, ctx);
    expect(listResult.output).toContain("design.md");
    expect(listResult.output).toContain("test-module: 1 attachment(s)");

    // The attach tool's data carries the doc id; use it for detach.
    const docId = (attachResult.data as { document: { id: string } }).document.id;
    const detachResult = await detach.execute({ id: docId }, ctx);
    expect(detachResult.ok).toBe(true);
    expect(detachResult.output).toContain("Detached");

    const finalList = await list.execute({}, ctx);
    expect(finalList.output).toContain("no attachments");
  });

  it("attach refuses when source is missing and never writes the scope file", async () => {
    const root = tempRoot();
    const ctx = createMockToolContext({ cwd: root, target: root });
    const attach = createAttachmentTools("test-module", TEST_SPEC).find(
      (t) => t.name === "test-module:attach",
    )!;
    const result = await attach.execute({}, ctx);
    expect(result.ok).toBe(false);
    expect(result.output).toContain("Usage: attach");
    expect(existsSync(path.join(root, ".kuzushi/test-module/attachments.json"))).toBe(false);
  });

  it("reparse re-runs the parser for an existing entry", async () => {
    const root = tempRoot();
    const file = path.join(root, "doc.md");
    writeFileSync(file, "first body");
    const ctx = createMockToolContext({ cwd: root, target: root });
    const tools = createAttachmentTools("test-module", TEST_SPEC);
    const attach = tools.find((t) => t.name === "test-module:attach")!;
    const reparse = tools.find((t) => t.name === "test-module:reparse")!;

    const attached = await attach.execute({ source: file }, ctx);
    const docId = (attached.data as { document: { id: string } }).document.id;

    writeFileSync(file, "second body that is much longer than the first");
    const reparseResult = await reparse.execute({ id: docId }, ctx);
    expect(reparseResult.ok).toBe(true);
    const list = tools.find((t) => t.name === "test-module:attachments")!;
    const listResult = await list.execute({ format: "json" }, ctx);
    const parsed = JSON.parse(listResult.output) as { documents: AttachmentDocument<TestKind>[] };
    expect(parsed.documents[0]?.extracted?.text).toContain("much longer");
  });

  it("afterMutation fires on every successful mutation with the up-to-date doc list", async () => {
    const root = tempRoot();
    const file = path.join(root, "design.md");
    writeFileSync(file, "the body");
    const ctx = createMockToolContext({ cwd: root, target: root });
    const calls: number[] = [];
    const tools = createAttachmentTools("test-module", TEST_SPEC, {
      afterMutation: ({ documents }) => calls.push(documents.length),
    });
    const attach = tools.find((t) => t.name === "test-module:attach")!;
    const detach = tools.find((t) => t.name === "test-module:detach")!;

    await attach.execute({ source: file }, ctx);
    expect(calls.at(-1)).toBe(1);
    const list = tools.find((t) => t.name === "test-module:attachments")!;
    const listResult = await list.execute({ format: "json" }, ctx);
    const docId =
      (JSON.parse(listResult.output) as { documents: Array<{ id: string }> }).documents[0]?.id ??
      "";
    await detach.execute({ id: docId }, ctx);
    expect(calls.at(-1)).toBe(0);
  });
});

function mkDoc(
  id: string,
  title: string,
  status: AttachmentDocument<TestKind>["status"] = "parsed",
): AttachmentDocument<TestKind> {
  return {
    id,
    source: `/tmp/${title}`,
    sourceType: "local",
    kind: "design-doc",
    title,
    status,
    extracted: status === "parsed" ? { text: "body", charCount: 4, parser: "text" } : undefined,
    parseWarnings: [],
    attachedAt: "2026-04-27T00:00:00.000Z",
  };
}
