import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  type Stats,
} from "node:fs";
import { isAbsolute, posix } from "node:path";
import { TextDecoder } from "node:util";
import type { GroundTruthDataset, GroundTruthEntry } from "./types.js";

const DATASET_KEYS = new Set(["name", "language", "repoUrl", "repoRef", "entries"]);
const ENTRY_KEYS = new Set(["id", "file", "line", "cwe", "isVulnerable", "category"]);
const MAX_GROUND_TRUTH_BYTES = 4 * 1024 * 1024;
const MAX_ENTRIES = 100_000;
const MAX_SOURCE_LINE = 10_000_000;

export function loadGroundTruth(path: string): GroundTruthDataset {
  const body = readGroundTruthFile(path);
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (error) {
    throw new Error(`Ground truth is not valid JSON: ${errorMessage(error)}`);
  }
  return validateDataset(parsed);
}

function readGroundTruthFile(path: string): string {
  const pathMetadata = lstatSync(path);
  assertRegularGroundTruth(path, pathMetadata);
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const openedMetadata = fstatSync(descriptor);
    assertSameGroundTruthFile(path, pathMetadata, openedMetadata);
    assertGroundTruthSize(path, openedMetadata.size);
    return readBoundedUtf8(descriptor, path);
  } finally {
    closeSync(descriptor);
  }
}

function assertRegularGroundTruth(path: string, metadata: Stats): void {
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`Ground truth must be a regular non-symlink file: ${path}`);
  }
  assertGroundTruthSize(path, metadata.size);
}

function assertSameGroundTruthFile(path: string, expected: Stats, opened: Stats): void {
  if (!opened.isFile() || expected.dev !== opened.dev || expected.ino !== opened.ino) {
    throw new Error(`Ground truth changed while it was being opened: ${path}`);
  }
}

function assertGroundTruthSize(path: string, size: number): void {
  if (size > MAX_GROUND_TRUTH_BYTES) {
    throw new Error(`Ground truth exceeds ${MAX_GROUND_TRUTH_BYTES} bytes: ${path}`);
  }
}

function readBoundedUtf8(descriptor: number, path: string): string {
  const buffer = Buffer.alloc(MAX_GROUND_TRUTH_BYTES + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const count = readSync(descriptor, buffer, offset, buffer.length - offset, null);
    if (count === 0) break;
    offset += count;
  }
  assertGroundTruthSize(path, offset);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, offset));
  } catch {
    throw new Error(`Ground truth is not valid UTF-8: ${path}`);
  }
}

export function validateDataset(value: unknown): GroundTruthDataset {
  const dataset = requiredRecord(value, "Ground truth");
  rejectUnknownKeys(dataset, DATASET_KEYS, "Ground truth");
  const entries = requiredArray(dataset.entries, "Ground truth.entries");
  if (entries.length === 0 || entries.length > MAX_ENTRIES) {
    throw new Error(`Ground truth.entries must contain 1..${MAX_ENTRIES} records`);
  }
  const repoUrl = requiredRepositoryUrl(dataset.repoUrl);
  const result: GroundTruthDataset = {
    name: requiredString(dataset.name, "Ground truth.name", 256),
    language: requiredString(dataset.language, "Ground truth.language", 128),
    repoUrl,
    repoRef: requiredRepositoryRef(dataset.repoRef, repoUrl),
    entries: entries.map((entry, index) => validateEntry(entry, index)),
  };
  rejectDuplicateIds(result.entries);
  return result;
}

function validateEntry(value: unknown, index: number): GroundTruthEntry {
  const label = `Ground truth.entries[${index}]`;
  const entry = requiredRecord(value, label);
  rejectUnknownKeys(entry, ENTRY_KEYS, label);
  const category = optionalString(entry.category, `${label}.category`, 256);
  return {
    id: requiredString(entry.id, `${label}.id`, 256),
    file: requiredRelativePath(entry.file, `${label}.file`),
    line: requiredLine(entry.line, `${label}.line`),
    cwe: requiredCwe(entry.cwe, `${label}.cwe`),
    isVulnerable: requiredBoolean(entry.isVulnerable, `${label}.isVulnerable`),
    ...(category === undefined ? {} : { category }),
  };
}

function requiredRepositoryUrl(value: unknown): string {
  const raw = requiredString(value, "Ground truth.repoUrl", 2_048);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("Ground truth.repoUrl must be an absolute URL");
  }
  if (url.protocol !== "https:" && url.protocol !== "fixture:") {
    throw new Error("Ground truth.repoUrl must use https: or fixture:");
  }
  return raw;
}

function requiredRepositoryRef(value: unknown, repoUrl: string): string {
  const revision = requiredString(value, "Ground truth.repoRef", 256);
  if (new URL(repoUrl).protocol === "fixture:") return revision;
  const commit = /^[a-f\d]{40}(?:[a-f\d]{24})?$/iu.test(revision);
  if (!commit) {
    throw new Error("Ground truth.repoRef must be an immutable full commit digest");
  }
  return revision;
}

function requiredRelativePath(value: unknown, label: string): string {
  const path = requiredString(value, label, 1_024);
  if (path.includes("\\") || path.includes("\0") || isAbsolute(path) || posix.isAbsolute(path)) {
    throw new Error(`${label} must be a portable relative path`);
  }
  if (posix.normalize(path) !== path || path === "." || path.startsWith("../")) {
    throw new Error(`${label} must not contain traversal or redundant segments`);
  }
  return path;
}

function requiredLine(value: unknown, label: string): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) <= 0 ||
    (value as number) > MAX_SOURCE_LINE
  ) {
    throw new Error(`${label} must be an integer from 1 through ${MAX_SOURCE_LINE}`);
  }
  return value as number;
}

function requiredCwe(value: unknown, label: string): string {
  const cwe = requiredString(value, label, 10);
  if (!/^CWE-(?!0+$)\d{1,6}$/u.test(cwe)) {
    throw new Error(`${label} must use canonical CWE-<digits> form`);
  }
  return cwe;
}

function rejectDuplicateIds(entries: GroundTruthEntry[]): void {
  const ids = new Set<string>();
  for (const entry of entries) {
    if (ids.has(entry.id)) throw new Error(`Ground truth contains duplicate id: ${entry.id}`);
    ids.add(entry.id);
  }
}

function requiredRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requiredArray(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function requiredString(value: unknown, label: string, maxBytes: number): string {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    throw new Error(`${label} must be a nonempty, unpadded string`);
  }
  if (Buffer.byteLength(value) > maxBytes || /[\0\r\n]/u.test(value)) {
    throw new Error(`${label} is too large or contains a forbidden control character`);
  }
  return value;
}

function optionalString(value: unknown, label: string, maxBytes: number): string | undefined {
  return value === undefined ? undefined : requiredString(value, label, maxBytes);
}

function requiredBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function rejectUnknownKeys(
  value: Record<string, unknown>,
  allowed: Set<string>,
  label: string,
): void {
  const unknown = Object.keys(value)
    .filter((key) => !allowed.has(key))
    .sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
