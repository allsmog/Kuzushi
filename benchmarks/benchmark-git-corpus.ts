import { spawnSync } from "node:child_process";
import { lstatSync, realpathSync } from "node:fs";
import { posix, resolve, win32 } from "node:path";
import {
  CORPUS_LIMITS,
  checkedCorpusTotal,
  decodeCorpusUtf8,
  type MaterializedTreeEntry,
} from "./benchmark-corpus-contract.js";

const FULL_OBJECT_ID = /^(?:[a-f\d]{40}|[a-f\d]{64})$/u;
const WINDOWS_DRIVE_PREFIX = /^[a-z]:/iu;
const TREE_RECORD = /^([0-7]{6}) ([a-z]+) ([a-f\d]{40}|[a-f\d]{64}) +([\d-]+)$/u;
const BATCH_HEADER = /^([a-f\d]{40}|[a-f\d]{64}) ([a-z]+) (\d+)$/u;

interface TreeEntryWithoutBytes {
  mode: MaterializedTreeEntry["mode"];
  objectId: string;
  path: string;
  size: number;
}

export function loadMaterializedTree(
  sourceRepo: string,
  revision: string,
): MaterializedTreeEntry[] {
  assertFullRevision(revision);
  const sourceRoot = verifiedSourceDirectory(sourceRepo);
  const entries = loadTreeEntries(sourceRoot, revision);
  const blobs = loadBlobs(sourceRoot, entries);
  return entries.map((entry, index) => ({ ...entry, bytes: blobs[index] }));
}

function assertFullRevision(revision: string): void {
  if (!FULL_OBJECT_ID.test(revision)) {
    throw new Error("Materialized benchmark revision must be an immutable full object ID");
  }
}

function verifiedSourceDirectory(sourceRepo: string): string {
  const requested = resolve(sourceRepo);
  const metadata = lstatSync(requested, { bigint: true });
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`Benchmark source must be a non-symlink directory: ${requested}`);
  }
  return realpathSync(requested);
}

function loadTreeEntries(sourceRoot: string, revision: string): TreeEntryWithoutBytes[] {
  const output = boundedGit(sourceRoot, [
    "ls-tree",
    "-r",
    "-l",
    "-z",
    "--full-tree",
    revision,
    "--",
  ]);
  const records = splitNullRecords(output);
  assertEntryCount(records.length);
  return parseAndBudgetEntries(records);
}

function assertEntryCount(count: number): void {
  if (count > CORPUS_LIMITS.entryCount) {
    throw new Error(`Benchmark commit contains more than ${CORPUS_LIMITS.entryCount} entries`);
  }
}

function splitNullRecords(output: Buffer): Buffer[] {
  if (output.length === 0) return [];
  assertNullTerminated(output);
  const records: Buffer[] = [];
  let start = 0;
  while (start < output.length) {
    const end = output.indexOf(0, start);
    records.push(nonemptyRecord(output, start, end));
    start = end + 1;
  }
  return records;
}

function assertNullTerminated(output: Buffer): void {
  if (output.at(-1) !== 0) throw new Error("git ls-tree returned an unterminated record");
}

function nonemptyRecord(output: Buffer, start: number, end: number): Buffer {
  if (end <= start) throw new Error("git ls-tree returned an empty record");
  return output.subarray(start, end);
}

function parseAndBudgetEntries(records: Buffer[]): TreeEntryWithoutBytes[] {
  const entries: TreeEntryWithoutBytes[] = [];
  const budget = { pathBytes: 0, blobBytes: 0, symlinks: 0 };
  for (const record of records) {
    const entry = parseTreeEntry(record);
    applyTreeBudget(entry, budget);
    entries.push(entry);
  }
  assertNoPathConflicts(entries);
  return entries;
}

function applyTreeBudget(
  entry: TreeEntryWithoutBytes,
  budget: { pathBytes: number; blobBytes: number; symlinks: number },
): void {
  budget.pathBytes = checkedCorpusTotal(
    budget.pathBytes,
    Buffer.byteLength(entry.path),
    CORPUS_LIMITS.totalPathBytes,
    "path bytes",
  );
  budget.blobBytes = checkedCorpusTotal(
    budget.blobBytes,
    entry.size,
    CORPUS_LIMITS.totalBlobBytes,
    "blob bytes",
  );
  if (entry.mode === "120000") assertSymlinkBudget(++budget.symlinks);
}

function assertSymlinkBudget(count: number): void {
  if (count > CORPUS_LIMITS.symlinkCount) {
    throw new Error(`Benchmark commit contains more than ${CORPUS_LIMITS.symlinkCount} symlinks`);
  }
}

function parseTreeEntry(record: Buffer): TreeEntryWithoutBytes {
  const separator = record.indexOf(0x09);
  if (separator <= 0) throw new Error("git ls-tree returned a malformed record");
  const parsed = parseTreeMetadata(record.subarray(0, separator));
  const path = parseTreePath(record.subarray(separator + 1));
  return { ...parsed, path };
}

function parseTreeMetadata(metadataBytes: Buffer): Omit<TreeEntryWithoutBytes, "path"> {
  const metadata = decodeCorpusUtf8(metadataBytes, "tree metadata");
  const match = TREE_RECORD.exec(metadata);
  if (!match) throw new Error(`git ls-tree returned malformed metadata: ${metadata}`);
  const [, mode, type, objectId, rawSize] = match;
  assertSupportedTreeType(mode, type);
  return {
    mode: mode as TreeEntryWithoutBytes["mode"],
    objectId,
    size: parseBoundedSize(rawSize, CORPUS_LIMITS.blobBytes, "blob"),
  };
}

function assertSupportedTreeType(mode: string, type: string): void {
  if (mode === "160000" || type === "commit") {
    throw new Error("Benchmark commit must not contain Git submodules");
  }
  const supportedMode = mode === "100644" || mode === "100755" || mode === "120000";
  if (type !== "blob" || !supportedMode) {
    throw new Error(`Benchmark commit contains unsupported Git entry mode ${mode} (${type})`);
  }
}

function parseTreePath(pathBytes: Buffer): string {
  if (pathBytes.length > CORPUS_LIMITS.pathBytes) {
    throw new Error(`Benchmark commit path exceeds ${CORPUS_LIMITS.pathBytes} bytes`);
  }
  const path = decodeCorpusUtf8(pathBytes, "tree path");
  assertSafeTreePath(path);
  return path;
}

function assertSafeTreePath(path: string): void {
  assertPortablePath(path);
  assertSafePathSegments(path);
}

function assertPortablePath(path: string): void {
  if (path.length === 0 || path.includes("\\") || path.includes("\0")) {
    throw new Error(`Benchmark commit contains an unsafe path: ${JSON.stringify(path)}`);
  }
  if (posix.isAbsolute(path) || win32.isAbsolute(path) || WINDOWS_DRIVE_PREFIX.test(path)) {
    throw new Error(`Benchmark commit contains an absolute path: ${JSON.stringify(path)}`);
  }
}

function assertSafePathSegments(path: string): void {
  const segments = path.split("/");
  if (segments.some(isDotOrEmpty)) {
    throw new Error(
      `Benchmark commit contains a dot or empty path segment: ${JSON.stringify(path)}`,
    );
  }
  if (segments.some((segment) => segment.toLowerCase() === ".git")) {
    throw new Error(`Benchmark commit contains a reserved .git path: ${JSON.stringify(path)}`);
  }
}

function isDotOrEmpty(segment: string): boolean {
  return segment.length === 0 || segment === "." || segment === "..";
}

function assertNoPathConflicts(entries: TreeEntryWithoutBytes[]): void {
  const paths = uniquePaths(entries);
  for (const path of paths) assertNoParentConflict(path, paths);
}

function uniquePaths(entries: TreeEntryWithoutBytes[]): Set<string> {
  const paths = new Set<string>();
  for (const entry of entries) {
    if (paths.has(entry.path)) throw new Error(`Benchmark commit repeats path ${entry.path}`);
    paths.add(entry.path);
  }
  return paths;
}

function assertNoParentConflict(path: string, paths: Set<string>): void {
  let parent = posix.dirname(path);
  while (parent !== ".") {
    if (paths.has(parent)) throw new Error(`Benchmark commit has conflicting path ${parent}`);
    parent = posix.dirname(parent);
  }
}

function parseBoundedSize(raw: string, maximum: number, label: string): number {
  if (!/^\d+$/u.test(raw)) throw new Error(`Benchmark ${label} size is not a nonnegative integer`);
  const size = Number(raw);
  if (!Number.isSafeInteger(size) || size > maximum) {
    throw new Error(`Benchmark ${label} exceeds ${maximum} bytes`);
  }
  return size;
}

function loadBlobs(sourceRoot: string, entries: TreeEntryWithoutBytes[]): Buffer[] {
  const objectIds = entries.map((entry) => entry.objectId).join("\n");
  const input = objectIds.length === 0 ? Buffer.alloc(0) : Buffer.from(`${objectIds}\n`, "ascii");
  const expectedBytes = entries.reduce((total, entry) => total + entry.size, 0);
  const maxBuffer = expectedBytes + CORPUS_LIMITS.batchProtocolOverheadBytes;
  const output = boundedGit(sourceRoot, ["cat-file", "--batch"], input, maxBuffer);
  return parseBatchOutput(output, entries);
}

function parseBatchOutput(output: Buffer, entries: TreeEntryWithoutBytes[]): Buffer[] {
  const state = { cursor: 0 };
  const blobs = entries.map((entry) => readBatchBlob(output, state, entry));
  if (state.cursor !== output.length) {
    throw new Error("git cat-file returned unexpected trailing output");
  }
  return blobs;
}

function readBatchBlob(
  output: Buffer,
  state: { cursor: number },
  entry: TreeEntryWithoutBytes,
): Buffer {
  const headerEnd = batchHeaderEnd(output, state.cursor);
  const header = parseBatchHeader(output.subarray(state.cursor, headerEnd));
  assertBatchMetadata(header, entry);
  const blobStart = headerEnd + 1;
  const blobEnd = blobStart + header.size;
  assertCompleteBatchBlob(output, blobEnd, entry.path);
  state.cursor = blobEnd + 1;
  return Buffer.from(output.subarray(blobStart, blobEnd));
}

function batchHeaderEnd(output: Buffer, cursor: number): number {
  const headerEnd = output.indexOf(0x0a, cursor);
  if (headerEnd < cursor || headerEnd - cursor > 256) {
    throw new Error("git cat-file returned a malformed batch header");
  }
  return headerEnd;
}

function parseBatchHeader(bytes: Buffer): { objectId: string; type: string; size: number } {
  const header = decodeCorpusUtf8(bytes, "batch header");
  const match = BATCH_HEADER.exec(header);
  if (!match) throw new Error(`git cat-file returned an invalid object header: ${header}`);
  return {
    objectId: match[1],
    type: match[2],
    size: parseBoundedSize(match[3], CORPUS_LIMITS.blobBytes, "batch blob"),
  };
}

function assertBatchMetadata(
  header: { objectId: string; type: string; size: number },
  entry: TreeEntryWithoutBytes,
): void {
  if (header.objectId !== entry.objectId || header.type !== "blob" || header.size !== entry.size) {
    throw new Error(`git cat-file metadata disagrees with ls-tree for ${entry.path}`);
  }
}

function assertCompleteBatchBlob(output: Buffer, blobEnd: number, path: string): void {
  if (blobEnd >= output.length || output[blobEnd] !== 0x0a) {
    throw new Error(`git cat-file returned truncated bytes for ${path}`);
  }
}

function boundedGit(
  sourceRoot: string,
  args: string[],
  input?: Buffer,
  maxBuffer = CORPUS_LIMITS.treeOutputBytes,
): Buffer {
  const result = spawnSync("git", ["--no-replace-objects", "-C", sourceRoot, ...args], {
    input,
    encoding: null,
    timeout: CORPUS_LIMITS.gitTimeoutMs,
    maxBuffer,
    stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw gitFailure(args[0], result.stderr);
  if (result.stdout.length > maxBuffer) {
    throw new Error(`git ${args[0]} exceeded its output budget`);
  }
  return result.stdout;
}

function gitFailure(command: string, stderr: Buffer): Error {
  return new Error(`git ${command} failed: ${decodeCorpusUtf8(stderr, "git stderr").trim()}`);
}
