/**
 * Tool factory that produces the four operator-facing attachment verbs for a
 * module: `<id>:attach`, `<id>:attachments`, `<id>:detach`, `<id>:reparse`.
 *
 * The factory is generic over `Id` (the module id literal type) so consumers
 * that use `defineModule` get template-literal name typing for free; modules
 * that build a plain `CopilotModule` value can leave Id as the default
 * `string` and the returned array is just `ModuleTool[]`.
 */

import path from "node:path";
import type { ExecutionContext, ModuleTool, ToolResult } from "../../types.js";
import { attachDocument, DEFAULT_MAX_BYTES } from "./documents.js";
import { defaultAttachmentAdapter, removeAttachment, upsertAttachment } from "./storage.js";
import type { AttachmentDocument, AttachmentStorageAdapter, KindSpec } from "./types.js";

/** Pull-out type so callers using `defineModule` get literal-typed names. */
export type AttachmentTool<Id extends string = string> = ModuleTool & {
  readonly name: `${Id}:${string}`;
};

interface AttachInput {
  source?: string;
  path?: string;
  url?: string;
  target?: string;
  kind?: string;
  title?: string;
  metadataOnly?: boolean;
  maxBytes?: number;
}

interface DetachInput {
  id?: string;
  target?: string;
}

interface ReparseInput {
  id?: string;
  target?: string;
}

interface AttachmentsListInput {
  format?: "table" | "json";
  target?: string;
}

/**
 * Slice published to `shell.kbState[moduleId]` so the `/kb` view and the
 * per-module-home `AttachmentsBlock` render the same data without each
 * needing to read the JSON file directly.
 */
export interface AttachmentsHomeSlice {
  moduleId: string;
  scopePath: string;
  documents: Array<AttachmentHomeRow>;
  totals: {
    total: number;
    parsed: number;
    needsReview: number;
    metadata: number;
    error: number;
  };
}

export interface AttachmentHomeRow {
  id: string;
  title: string;
  kind: string;
  kindLabel: string;
  status: AttachmentDocument["status"];
  sourceType: "local" | "url";
  source: string;
  sizeBytes?: number;
  charCount?: number;
  attachedAt: string;
  /** "12.4k · 1d ago", "needs review", "fetch failed", etc. */
  detail: string;
  parseWarnings: string[];
}

export interface CreateAttachmentToolsOptions<K extends string> {
  /**
   * Custom storage adapter. Defaults to `defaultAttachmentAdapter(spec.moduleId)`
   * which writes to `.kuzushi/<moduleId>/attachments.json`. Vendor passes a
   * custom adapter so it keeps using `scope.draft.json`.
   */
  adapter?: AttachmentStorageAdapter<K>;
  /**
   * Hook that fires after every successful mutation (attach/detach/reparse).
   * Modules use it to patch their own home-view slice (e.g. vendor's
   * `scopeToHomeSlice` derives missing-artifact hints that the generic slice
   * doesn't know about).
   */
  afterMutation?: (input: {
    ctx: ExecutionContext;
    cwd: string;
    documents: AttachmentDocument<K>[];
  }) => void;
}

export function createAttachmentTools<Id extends string, K extends string>(
  moduleId: Id,
  spec: KindSpec<K>,
  options: CreateAttachmentToolsOptions<K> = {},
): AttachmentTool<Id>[] {
  if (spec.moduleId !== moduleId) {
    throw new Error(
      `createAttachmentTools: moduleId "${moduleId}" does not match KindSpec.moduleId "${spec.moduleId}".`,
    );
  }
  const adapter = options.adapter ?? defaultAttachmentAdapter<K>(moduleId);
  const afterMutation = options.afterMutation;

  const attachTool: ModuleTool = {
    name: `${moduleId}:attach`,
    displayName: "Attach",
    description: `Attach a local file or URL to the ${moduleId} knowledge base. Text/Markdown/JSON/CSV/YAML/XML/HTML are parsed natively; PDFs use a lightweight text extractor; images and unsupported types are retained as metadata-only references. The content is included in this module's LLM prompts as untrusted reference material.`,
    inputSchema: {
      type: "object",
      properties: {
        source: { type: "string", description: "Local path or URL to attach." },
        path: { type: "string", description: "Alias for source." },
        url: { type: "string", description: "Alias for source." },
        target: { type: "string", description: "Positional alias for source." },
        kind: {
          type: "string",
          enum: [...spec.kinds],
          description: "Optional kind override. Inferred from filename when omitted.",
        },
        title: { type: "string", description: "Optional display title." },
        metadataOnly: {
          type: "boolean",
          description: "Skip parsing; retain the path/URL as a metadata-only reference.",
        },
        maxBytes: {
          type: "integer",
          minimum: 1024,
          description: `Per-file cap in bytes. Defaults to ${DEFAULT_MAX_BYTES}.`,
        },
      },
    },
    headless: true,
    formatInput(input: unknown) {
      const params = input as AttachInput | undefined;
      return params?.source ?? params?.path ?? params?.url ?? params?.target ?? null;
    },
    renderResult(result) {
      const first = result.output.split("\n", 1)[0]?.trim();
      return first && first.length > 0 ? first : null;
    },
    async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
      const params = readInput<AttachInput>(input);
      const source = params.source ?? params.path ?? params.url ?? params.target;
      if (!source?.trim()) {
        return {
          ok: false,
          output: `Usage: attach <path-or-url> [kind=${spec.kinds.join("|")}] [title=<text>] [metadataOnly=true]`,
        };
      }
      const cwd = resolveCwd(ctx);
      const doc = attachDocument(
        {
          source,
          cwd,
          ...(params.kind !== undefined ? { kind: params.kind } : {}),
          ...(params.title !== undefined ? { title: params.title } : {}),
          ...(params.metadataOnly !== undefined ? { metadataOnly: params.metadataOnly } : {}),
        },
        spec,
        params.maxBytes !== undefined ? { maxBytes: params.maxBytes } : {},
      );
      const existing = adapter.read(cwd);
      const next = upsertAttachment(existing, doc);
      const filePath = adapter.write(cwd, next);
      afterMutation?.({ ctx, cwd, documents: next });
      patchHomeSlice(ctx, moduleId, buildHomeSlice(moduleId, filePath, next, spec));

      const lines = formatAttachLines(doc, filePath, spec);
      return {
        ok: doc.status !== "error",
        output: lines.join("\n"),
        data: { document: doc, scopePath: filePath, total: next.length },
      };
    },
  };

  const attachmentsTool: ModuleTool = {
    name: `${moduleId}:attachments`,
    displayName: "Attachments",
    description: `List the documents currently attached to the ${moduleId} knowledge base. Output includes id, kind, status, size, and source path so operators can decide what to detach or reparse.`,
    inputSchema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          enum: ["table", "json"],
          description: "Output format. Defaults to table.",
        },
        target: { type: "string", description: "Shell target passthrough." },
      },
    },
    headless: true,
    async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
      const params = readInput<AttachmentsListInput>(input);
      const cwd = resolveCwd(ctx);
      const docs = adapter.read(cwd);
      const filePath = adapter.pathFor(cwd);
      patchHomeSlice(ctx, moduleId, buildHomeSlice(moduleId, filePath, docs, spec));

      if (params.format === "json") {
        return {
          ok: true,
          output: JSON.stringify({ moduleId, scopePath: filePath, documents: docs }, null, 2),
          data: { documents: docs, scopePath: filePath },
        };
      }
      const output = formatAttachmentsTable(moduleId, filePath, docs, spec);
      return { ok: true, output, data: { documents: docs, scopePath: filePath } };
    },
  };

  const detachTool: ModuleTool = {
    name: `${moduleId}:detach`,
    displayName: "Detach",
    description: `Remove an attachment from the ${moduleId} knowledge base by id, unique id-prefix, or unique title.`,
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Attachment id, unique id-prefix, or unique title." },
        target: { type: "string", description: "Positional alias for id." },
      },
    },
    headless: true,
    async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
      const params = readInput<DetachInput>(input);
      const identifier = params.id ?? params.target ?? "";
      if (!identifier.trim()) {
        return {
          ok: false,
          output: `Usage: detach <id|prefix|title>. List attachments first with \`attachments\`.`,
        };
      }
      const cwd = resolveCwd(ctx);
      const docs = adapter.read(cwd);
      const result = removeAttachment(docs, identifier);
      if (result.ambiguous) {
        const lines = [
          `Identifier "${identifier}" matched ${result.matches.length} attachments — be more specific:`,
        ];
        for (const m of result.matches) lines.push(`  ${m.id}  ${m.title}  (${m.kind})`);
        return { ok: false, output: lines.join("\n") };
      }
      if (!result.removed) {
        return {
          ok: false,
          output: `No attachment matched "${identifier}". List with \`attachments\`.`,
        };
      }
      const filePath = adapter.write(cwd, result.docs);
      afterMutation?.({ ctx, cwd, documents: result.docs });
      patchHomeSlice(ctx, moduleId, buildHomeSlice(moduleId, filePath, result.docs, spec));
      return {
        ok: true,
        output: `Detached ${result.removed.title} (id ${result.removed.id})`,
        data: { document: result.removed, total: result.docs.length },
      };
    },
  };

  const reparseTool: ModuleTool = {
    name: `${moduleId}:reparse`,
    displayName: "Reparse",
    description: `Re-run the attachment parser for an existing entry — useful after the underlying file changed on disk.`,
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Attachment id or unique id-prefix." },
        target: { type: "string", description: "Positional alias for id." },
      },
    },
    headless: true,
    async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
      const params = readInput<ReparseInput>(input);
      const identifier = params.id ?? params.target ?? "";
      if (!identifier.trim()) {
        return {
          ok: false,
          output: `Usage: reparse <id|prefix>. List attachments first with \`attachments\`.`,
        };
      }
      const cwd = resolveCwd(ctx);
      const docs = adapter.read(cwd);
      const target = findByIdOrPrefix(docs, identifier);
      if (!target) {
        return {
          ok: false,
          output: `No attachment matched "${identifier}". List with \`attachments\`.`,
        };
      }
      const refreshed = attachDocument(
        { source: target.source, cwd, kind: target.kind, title: target.title },
        spec,
      );
      const next = upsertAttachment(docs, refreshed);
      const filePath = adapter.write(cwd, next);
      afterMutation?.({ ctx, cwd, documents: next });
      patchHomeSlice(ctx, moduleId, buildHomeSlice(moduleId, filePath, next, spec));

      const lines = [
        `Reparsed ${refreshed.title} (id ${refreshed.id}, status ${refreshed.status}).`,
      ];
      if (refreshed.parseWarnings.length > 0) {
        lines.push("Warnings:");
        for (const warning of refreshed.parseWarnings) lines.push(`  - ${warning}`);
      }
      return {
        ok: refreshed.status !== "error",
        output: lines.join("\n"),
        data: { document: refreshed },
      };
    },
  };

  return [attachTool, attachmentsTool, detachTool, reparseTool] as AttachmentTool<Id>[];
}

function readInput<T>(input: unknown): T {
  return input && typeof input === "object" && !Array.isArray(input) ? (input as T) : ({} as T);
}

function resolveCwd(ctx: ExecutionContext): string {
  return path.resolve(ctx.cwd);
}

function findByIdOrPrefix<K extends string>(
  docs: ReadonlyArray<AttachmentDocument<K>>,
  identifier: string,
): AttachmentDocument<K> | null {
  const exact = docs.find((d) => d.id === identifier);
  if (exact) return exact;
  const prefix = docs.filter((d) => d.id.startsWith(identifier.toLowerCase()));
  return prefix.length === 1 ? prefix[0]! : null;
}

function formatAttachLines<K extends string>(
  doc: AttachmentDocument<K>,
  filePath: string,
  spec: KindSpec<K>,
): string[] {
  const lines = [`Attached ${doc.title} (${spec.label(doc.kind)}, ${doc.status})`];
  lines.push(`  id      ${doc.id}`);
  if (doc.extracted) {
    lines.push(`  parsed  ${doc.extracted.charCount} chars (${doc.extracted.parser})`);
  } else if (doc.sizeBytes !== undefined) {
    lines.push(`  size    ${formatBytes(doc.sizeBytes)}`);
  }
  lines.push(`  stored  ${filePath}`);
  if (doc.parseWarnings.length > 0) {
    lines.push("Warnings:");
    for (const warning of doc.parseWarnings) lines.push(`  - ${warning}`);
  }
  return lines;
}

function formatAttachmentsTable<K extends string>(
  moduleId: string,
  filePath: string,
  docs: ReadonlyArray<AttachmentDocument<K>>,
  spec: KindSpec<K>,
): string {
  if (docs.length === 0) {
    return [
      `${moduleId}: no attachments`,
      `Scope: ${filePath}`,
      `Use \`attach <path-or-url>\` to add reference material (kinds: ${spec.kinds.join(", ")}).`,
    ].join("\n");
  }
  const lines = [`${moduleId}: ${docs.length} attachment(s)`, `Scope: ${filePath}`, ""];
  lines.push("ID            STATUS  KIND               TITLE                              SIZE");
  for (const doc of docs) {
    const id = doc.id.padEnd(13);
    const status = statusGlyph(doc.status).padEnd(7);
    const kind = spec.label(doc.kind).slice(0, 18).padEnd(18);
    const title = doc.title.length > 35 ? `${doc.title.slice(0, 32)}...` : doc.title.padEnd(35);
    const size = formatSizeOrChars(doc);
    lines.push(`${id} ${status} ${kind} ${title} ${size}`);
  }
  return lines.join("\n");
}

function statusGlyph(status: AttachmentDocument["status"]): string {
  switch (status) {
    case "parsed":
      return "[x]";
    case "needs-human-review":
      return "[ ]";
    case "metadata-only":
      return "[~]";
    case "error":
      return "[!]";
    default:
      return "[?]";
  }
}

function formatSizeOrChars<K extends string>(doc: AttachmentDocument<K>): string {
  if (doc.extracted) return `${formatNumber(doc.extracted.charCount)} chars`;
  if (doc.sizeBytes !== undefined) return formatBytes(doc.sizeBytes);
  return "—";
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatNumber(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

/**
 * Build the slice the home view + `/kb` view consume. Pure — no I/O.
 */
export function buildHomeSlice<K extends string>(
  moduleId: string,
  scopePath: string,
  documents: ReadonlyArray<AttachmentDocument<K>>,
  spec: KindSpec<K>,
  now: number = Date.now(),
): AttachmentsHomeSlice {
  const totals = {
    total: documents.length,
    parsed: documents.filter((d) => d.status === "parsed").length,
    needsReview: documents.filter((d) => d.status === "needs-human-review").length,
    metadata: documents.filter((d) => d.status === "metadata-only").length,
    error: documents.filter((d) => d.status === "error").length,
  };
  const rows = documents.map<AttachmentHomeRow>((doc) => {
    const detail = describeDoc(doc, now);
    const row: AttachmentHomeRow = {
      id: doc.id,
      title: doc.title,
      kind: doc.kind,
      kindLabel: spec.label(doc.kind),
      status: doc.status,
      sourceType: doc.sourceType,
      source: doc.source,
      attachedAt: doc.attachedAt,
      detail,
      parseWarnings: doc.parseWarnings,
    };
    if (doc.sizeBytes !== undefined) row.sizeBytes = doc.sizeBytes;
    if (doc.extracted) row.charCount = doc.extracted.charCount;
    return row;
  });
  return { moduleId, scopePath, documents: rows, totals };
}

function describeDoc<K extends string>(doc: AttachmentDocument<K>, now: number): string {
  const age = formatAge(doc.attachedAt, now);
  if (doc.status === "error") {
    const first = doc.parseWarnings[0] ?? "error";
    return first.length > 40 ? `${first.slice(0, 37)}...` : first;
  }
  if (doc.status === "needs-human-review") return `needs review · ${age}`;
  if (doc.status === "metadata-only") {
    const size = doc.sizeBytes !== undefined ? formatBytes(doc.sizeBytes) : "—";
    return `${size} · ${age}`;
  }
  if (doc.extracted) return `${formatNumber(doc.extracted.charCount)} chars · ${age}`;
  return age;
}

function formatAge(iso: string, now: number): string {
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return "—";
  const delta = Math.max(0, now - then);
  if (delta < 60_000) return "just now";
  const minutes = Math.floor(delta / 60_000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function patchHomeSlice(
  ctx: ExecutionContext,
  moduleId: string,
  slice: AttachmentsHomeSlice,
): void {
  const state = ctx.uiStore?.getState();
  if (!state || typeof state !== "object" || !("shell" in state)) return;
  const shell = (state as { shell?: unknown }).shell;
  if (!shell || typeof shell !== "object") return;
  const shellRecord = shell as Record<string, unknown>;
  const existingKb = shellRecord["kbState"];
  const kbState =
    existingKb && typeof existingKb === "object" && !Array.isArray(existingKb)
      ? { ...(existingKb as Record<string, AttachmentsHomeSlice>) }
      : ({} as Record<string, AttachmentsHomeSlice>);
  kbState[moduleId] = slice;
  ctx.uiStore?.update({ shell: { ...shellRecord, kbState } });
}
