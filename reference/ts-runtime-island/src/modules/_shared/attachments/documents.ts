/**
 * Shared attachment parser. Lifted from `vendor-assessment/documents.ts`
 * with the kind enum factored out into a `KindSpec<K>` so each consuming
 * module can plug in its own taxonomy.
 *
 * Parser branches:
 *   - text/markdown/json/csv/yaml/xml/html → read as UTF-8, status = "parsed"
 *   - .pdf → lightweight regex extractor, status = "parsed" (≥ 100 chars) or "needs-human-review"
 *   - images (.png/.jpg/.gif/.svg/.webp) → status = "needs-human-review", no text
 *   - url (http/https) → status = "metadata-only" (URL fetching is intentionally
 *     out of scope until we have an allowlist + SSRF policy)
 *   - oversized files → status = "error" with a refusal warning
 *   - unknown extensions → status = "metadata-only"
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import type { AttachmentDocument, AttachmentStatus, KindSpec } from "./types.js";

const TEXT_EXTENSIONS = new Set([
  ".csv",
  ".html",
  ".htm",
  ".json",
  ".md",
  ".markdown",
  ".text",
  ".tsv",
  ".txt",
  ".xml",
  ".yaml",
  ".yml",
]);

const IMAGE_EXTENSIONS = new Set([".gif", ".jpeg", ".jpg", ".png", ".svg", ".webp"]);

/** Default per-attachment cap. Operators can override per-tool via `set <tool> maxBytes <n>`. */
export const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;

export interface AttachDocumentInput {
  /** Local path (relative to `cwd`) or URL. */
  source: string;
  /** Working directory used to resolve relative paths. */
  cwd: string;
  /** Optional kind override; falls back to filename inference and then `spec.default`. */
  kind?: string;
  /** Optional display title override. */
  title?: string;
  /**
   * When true, skip parsing even for known text/PDF extensions and store the
   * file as `metadata-only`. Lets operators stage references without burning
   * memory on huge logs.
   */
  metadataOnly?: boolean;
}

export interface AttachDocumentOptions {
  /** Per-attachment cap in bytes; oversized files become `status: "error"`. */
  maxBytes?: number;
}

export function attachDocument<K extends string>(
  input: AttachDocumentInput,
  spec: KindSpec<K>,
  opts: AttachDocumentOptions = {},
): AttachmentDocument<K> {
  const source = input.source.trim();
  const sourceType = isUrl(source) ? "url" : "local";
  const resolved = sourceType === "local" ? path.resolve(input.cwd, source) : source;
  const kind = inferKind(source, input.kind, spec);
  const now = new Date().toISOString();
  const id = documentId(resolved);
  const title = input.title?.trim() || titleFromSource(source);

  if (sourceType === "url") {
    return {
      id,
      source: resolved,
      sourceType,
      kind,
      title,
      status: "metadata-only",
      parseWarnings: [
        "URL fetching is not configured for this module yet; source retained in scope.",
      ],
      attachedAt: now,
    };
  }

  if (!existsSync(resolved)) {
    return {
      id,
      source: resolved,
      sourceType,
      kind,
      title,
      status: "error",
      parseWarnings: ["Local source does not exist."],
      attachedAt: now,
    };
  }

  const stat = statSync(resolved);
  if (!stat.isFile()) {
    return {
      id,
      source: resolved,
      sourceType,
      kind,
      title,
      sizeBytes: stat.size,
      status: "error",
      parseWarnings: ["Local source is not a regular file."],
      attachedAt: now,
    };
  }

  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  if (stat.size > maxBytes) {
    return {
      id,
      source: resolved,
      sourceType,
      kind,
      title,
      sizeBytes: stat.size,
      status: "error",
      parseWarnings: [
        `File is ${formatBytes(stat.size)}; the attachment cap is ${formatBytes(maxBytes)}. Pass metadataOnly=true to retain the path without parsing, or raise the cap with \`set ${spec.moduleId}:attach maxBytes <bytes>\`.`,
      ],
      attachedAt: now,
    };
  }

  const ext = path.extname(resolved).toLowerCase();
  const mime = mimeFromExtension(ext);
  const base = {
    id,
    source: resolved,
    sourceType: "local" as const,
    kind,
    title,
    mime,
    sizeBytes: stat.size,
    attachedAt: now,
  };

  if (input.metadataOnly) {
    return {
      ...base,
      status: "metadata-only",
      parseWarnings: ["Attached with metadataOnly=true; file content was not parsed."],
    };
  }

  if (TEXT_EXTENSIONS.has(ext)) {
    const text = readFileSync(resolved, "utf-8");
    return {
      ...base,
      status: "parsed",
      extracted: { text, charCount: text.length, parser: "text" },
      parseWarnings: [],
    };
  }

  if (ext === ".pdf") {
    const parsed = extractPdfTextLite(resolved);
    const status: AttachmentStatus =
      parsed.text.trim().length >= 100 ? "parsed" : "needs-human-review";
    return {
      ...base,
      pageCount: parsed.pageCount,
      status,
      extracted: { text: parsed.text, charCount: parsed.text.length, parser: "pdf-lite" },
      parseWarnings: parsed.warnings,
    };
  }

  if (IMAGE_EXTENSIONS.has(ext)) {
    return {
      ...base,
      status: "needs-human-review",
      parseWarnings: ["Image or diagram file retained in scope; human review required."],
    };
  }

  return {
    ...base,
    status: "metadata-only",
    parseWarnings: [`Unsupported file extension "${ext || "(none)"}"; source retained in scope.`],
  };
}

/**
 * Resolve a kind from an explicit override + spec inference rules. Exported
 * so the operator-facing tool layer can validate `kind=...` arguments before
 * calling `attachDocument`.
 */
export function inferKind<K extends string>(
  source: string,
  override: string | undefined,
  spec: KindSpec<K>,
): K {
  const normalized = override?.trim();
  if (normalized && (spec.kinds as readonly string[]).includes(normalized)) {
    return normalized as K;
  }
  const base = path.basename(source).toLowerCase();
  for (const rule of spec.inference) {
    if (rule.pattern.test(base)) return rule.kind;
  }
  return spec.default;
}

function documentId(source: string): string {
  return createHash("sha256").update(source).digest("hex").slice(0, 12);
}

function titleFromSource(source: string): string {
  if (isUrl(source)) {
    try {
      const url = new URL(source);
      return path.basename(url.pathname) || url.hostname;
    } catch {
      return source;
    }
  }
  return path.basename(source);
}

function isUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

function mimeFromExtension(ext: string): string | undefined {
  switch (ext) {
    case ".csv":
      return "text/csv";
    case ".html":
    case ".htm":
      return "text/html";
    case ".json":
      return "application/json";
    case ".md":
    case ".markdown":
      return "text/markdown";
    case ".pdf":
      return "application/pdf";
    case ".png":
      return "image/png";
    case ".jpg":
    case ".jpeg":
      return "image/jpeg";
    case ".svg":
      return "image/svg+xml";
    case ".txt":
    case ".text":
      return "text/plain";
    case ".xml":
      return "application/xml";
    case ".yaml":
    case ".yml":
      return "application/yaml";
    default:
      return undefined;
  }
}

function extractPdfTextLite(filePath: string): {
  text: string;
  pageCount?: number;
  warnings: string[];
} {
  const raw = readFileSync(filePath);
  const latin1 = raw.toString("latin1");
  const pageMatches = latin1.match(/\/Type\s*\/Page\b/g);
  const pageCount = pageMatches?.length;
  const chunks: string[] = [];
  const textBlocks = latin1.match(/BT[\s\S]*?ET/g) ?? [latin1];

  for (const block of textBlocks) {
    const literalMatches = block.matchAll(/\((?:\\.|[^\\)])*\)/g);
    for (const match of literalMatches) {
      const decoded = decodePdfLiteral(match[0].slice(1, -1));
      if (decoded.trim().length > 0) chunks.push(decoded);
    }
  }

  const text = chunks
    .join(" ")
    .replace(/[ \t]{2,}/g, " ")
    .replace(/\s+\n/g, "\n")
    .trim();
  const warnings = [
    "PDF text was extracted with a lightweight parser; verify quotes and page references before relying on the report.",
  ];
  if (text.length < 100) {
    warnings.push(
      "PDF produced little extractable text; it may be scanned, encrypted, or diagram-heavy.",
    );
  }
  return { text, ...(pageCount !== undefined ? { pageCount } : {}), warnings };
}

function decodePdfLiteral(value: string): string {
  return value
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\b/g, "\b")
    .replace(/\\f/g, "\f")
    .replace(/\\([()\\])/g, "$1")
    .replace(/\\\d{1,3}/g, " ");
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
