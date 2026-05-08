/**
 * Shared attachment storage. The default adapter persists at
 * `<cwd>/.kuzushi/<moduleId>/attachments.json` — same convention as the
 * existing per-module artifact paths (house-rules, prompt overrides). Vendor
 * keeps its `scope.draft.json` shape via a custom adapter declared in
 * `src/modules/vendor-assessment/storage.ts`.
 */

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { AttachmentDocument, AttachmentScope, AttachmentStorageAdapter } from "./types.js";

/** Resolve the on-disk path used by the default adapter. */
export function attachmentsPath(cwd: string, moduleId: string): string {
  return path.join(cwd, ".kuzushi", moduleId, "attachments.json");
}

/** Default adapter — JSON file persisted at `.kuzushi/<moduleId>/attachments.json`. */
export function defaultAttachmentAdapter<K extends string>(
  moduleId: string,
): AttachmentStorageAdapter<K> {
  return {
    pathFor(cwd) {
      return attachmentsPath(cwd, moduleId);
    },
    read(cwd) {
      const file = attachmentsPath(cwd, moduleId);
      if (!existsSync(file)) return [];
      try {
        const raw = JSON.parse(readFileSync(file, "utf-8")) as Partial<AttachmentScope<K>>;
        return Array.isArray(raw.documents) ? raw.documents.filter(isAttachmentDocument) : [];
      } catch {
        return [];
      }
    },
    write(cwd, docs) {
      const file = attachmentsPath(cwd, moduleId);
      mkdirSync(path.dirname(file), { recursive: true });
      const scope: AttachmentScope<K> = {
        documents: [...docs],
        updatedAt: new Date().toISOString(),
      };
      writeFileSync(file, `${JSON.stringify(scope, null, 2)}\n`);
      return file;
    },
    clear(cwd) {
      const file = attachmentsPath(cwd, moduleId);
      if (existsSync(file)) rmSync(file);
    },
  };
}

/** Insert or replace a document by id. Returns a new array (input is not mutated). */
export function upsertAttachment<K extends string>(
  docs: ReadonlyArray<AttachmentDocument<K>>,
  doc: AttachmentDocument<K>,
): AttachmentDocument<K>[] {
  const next = docs.filter((existing) => existing.id !== doc.id);
  next.push(doc);
  return next;
}

/**
 * Remove a document matched by exact id, unique id-prefix, or unique title.
 * Returns the new list and the removed doc (or `null` when nothing matched).
 * Ambiguous prefixes are rejected so the operator gets a clear error rather
 * than nondeterministic deletion.
 */
export function removeAttachment<K extends string>(
  docs: ReadonlyArray<AttachmentDocument<K>>,
  identifier: string,
):
  | { docs: AttachmentDocument<K>[]; removed: AttachmentDocument<K> | null; ambiguous: false }
  | {
      docs: AttachmentDocument<K>[];
      removed: null;
      ambiguous: true;
      matches: AttachmentDocument<K>[];
    } {
  const needle = identifier.trim();
  if (!needle) return { docs: [...docs], removed: null, ambiguous: false };

  const exactId = docs.find((doc) => doc.id === needle);
  if (exactId) {
    return {
      docs: docs.filter((doc) => doc.id !== exactId.id),
      removed: exactId,
      ambiguous: false,
    };
  }

  const lower = needle.toLowerCase();
  const idPrefix = docs.filter((doc) => doc.id.toLowerCase().startsWith(lower));
  if (idPrefix.length === 1) {
    const removed = idPrefix[0]!;
    return { docs: docs.filter((doc) => doc.id !== removed.id), removed, ambiguous: false };
  }
  if (idPrefix.length > 1) {
    return { docs: [...docs], removed: null, ambiguous: true, matches: idPrefix };
  }

  const titleMatches = docs.filter((doc) => doc.title.toLowerCase() === lower);
  if (titleMatches.length === 1) {
    const removed = titleMatches[0]!;
    return { docs: docs.filter((doc) => doc.id !== removed.id), removed, ambiguous: false };
  }
  if (titleMatches.length > 1) {
    return { docs: [...docs], removed: null, ambiguous: true, matches: titleMatches };
  }

  return { docs: [...docs], removed: null, ambiguous: false };
}

function isAttachmentDocument<K extends string>(value: unknown): value is AttachmentDocument<K> {
  if (!value || typeof value !== "object") return false;
  const v = value as Partial<AttachmentDocument<K>>;
  return (
    typeof v.id === "string" &&
    typeof v.source === "string" &&
    typeof v.kind === "string" &&
    typeof v.title === "string" &&
    typeof v.status === "string" &&
    Array.isArray(v.parseWarnings)
  );
}
