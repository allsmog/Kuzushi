import { createHash } from "node:crypto";
import {
  type BigIntStats,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readlinkSync,
  readSync,
} from "node:fs";
import { join } from "node:path";
import {
  CORPUS_LIMITS,
  type CorpusIdentity,
  type CorpusManifest,
  checkedCorpusTotal,
  decodeCorpusUtf8,
  isKuzushiStatePath,
  type ManifestEntry,
} from "./benchmark-corpus-contract.js";
import { assertCorpusRootIdentity } from "./benchmark-corpus-removal.js";

interface SnapshotBudget {
  entries: number;
  pathBytes: number;
  blobBytes: number;
}

export function snapshotCorpus(root: string, baseline?: CorpusManifest): CorpusManifest {
  const manifest = new Map<string, ManifestEntry>();
  const budget = initialBudget();
  walkDirectory(root, "", (absolutePath, relativePath, metadata) => {
    applySnapshotBudget(budget, relativePath, metadata);
    manifest.set(relativePath, manifestEntry(absolutePath, relativePath, metadata, baseline));
  });
  return manifest;
}

export function assertCorpusUnchanged(
  root: string,
  identity: CorpusIdentity,
  baseline: CorpusManifest,
): void {
  assertCorpusRootIdentity(root, identity);
  const current = snapshotCorpus(root, baseline);
  assertBaselineEntries(current, baseline);
  assertOnlyKuzushiExtras(current, baseline);
}

function initialBudget(): SnapshotBudget {
  return { entries: 0, pathBytes: 0, blobBytes: 0 };
}

function applySnapshotBudget(
  budget: SnapshotBudget,
  relativePath: string,
  metadata: BigIntStats,
): void {
  budget.entries += 1;
  assertSnapshotEntryCount(budget.entries);
  budget.pathBytes = checkedCorpusTotal(
    budget.pathBytes,
    Buffer.byteLength(relativePath),
    CORPUS_LIMITS.totalPathBytes,
    "path bytes",
  );
  if (metadata.isFile()) applySnapshotBlobBudget(budget, metadata);
}

function assertSnapshotEntryCount(count: number): void {
  if (count > CORPUS_LIMITS.entryCount) {
    throw new Error("Materialized corpus exceeds its entry budget");
  }
}

function applySnapshotBlobBudget(budget: SnapshotBudget, metadata: BigIntStats): void {
  budget.blobBytes = checkedCorpusTotal(
    budget.blobBytes,
    Number(metadata.size),
    CORPUS_LIMITS.totalBlobBytes,
    "blob bytes",
  );
}

function manifestEntry(
  absolutePath: string,
  relativePath: string,
  metadata: BigIntStats,
  baseline?: CorpusManifest,
): ManifestEntry {
  if (metadata.isDirectory()) return manifestDirectory(metadata.mode);
  if (metadata.isSymbolicLink())
    return manifestSymlink(absolutePath, relativePath, metadata, baseline);
  if (metadata.isFile()) return manifestFile(absolutePath, relativePath, metadata, baseline);
  throw new Error(`Materialized corpus contains an unsupported entry: ${relativePath}`);
}

function manifestDirectory(mode: bigint): ManifestEntry {
  return { type: "directory", mode: Number(mode & 0o777n), size: 0 };
}

function manifestSymlink(
  absolutePath: string,
  relativePath: string,
  metadata: BigIntStats,
  baseline?: CorpusManifest,
): ManifestEntry {
  assertGeneratedStateIsNotSymlink(relativePath, baseline);
  const target = readlinkNoFollow(absolutePath, metadata);
  return {
    type: "symlink",
    mode: Number(metadata.mode & 0o777n),
    size: Buffer.byteLength(target),
    target,
  };
}

function assertGeneratedStateIsNotSymlink(relativePath: string, baseline?: CorpusManifest): void {
  if (baseline && !baseline.has(relativePath) && isKuzushiStatePath(relativePath)) {
    throw new Error(`Generated Kuzushi state must not contain symlinks: ${relativePath}`);
  }
}

function manifestFile(
  absolutePath: string,
  relativePath: string,
  metadata: BigIntStats,
  baseline?: CorpusManifest,
): ManifestEntry {
  if (baseline && !baseline.has(relativePath) && isKuzushiStatePath(relativePath)) {
    return untrustedGeneratedFile(metadata);
  }
  return trustedSourceFile(absolutePath, metadata);
}

function untrustedGeneratedFile(metadata: BigIntStats): ManifestEntry {
  return {
    type: "file",
    mode: Number(metadata.mode & 0o777n),
    size: Number(metadata.size),
  };
}

function trustedSourceFile(path: string, metadata: BigIntStats): ManifestEntry {
  const size = Number(metadata.size);
  assertSourceFileSize(path, size);
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    return openedFileManifest(descriptor, path, metadata);
  } finally {
    closeSync(descriptor);
  }
}

function assertSourceFileSize(path: string, size: number): void {
  if (!Number.isSafeInteger(size) || size > CORPUS_LIMITS.blobBytes) {
    throw new Error(`Materialized corpus file exceeds ${CORPUS_LIMITS.blobBytes} bytes: ${path}`);
  }
}

function openedFileManifest(
  descriptor: number,
  path: string,
  expected: BigIntStats,
): ManifestEntry {
  const opened = fstatSync(descriptor, { bigint: true });
  assertOpenedFileIdentity(path, opened, expected);
  const size = Number(opened.size);
  assertSourceFileSize(path, size);
  const bytes = readExactFile(descriptor, size, path);
  return {
    type: "file",
    mode: Number(opened.mode & 0o777n),
    size: bytes.length,
    digest: createHash("sha256").update(bytes).digest("hex"),
  };
}

function readExactFile(descriptor: number, size: number, path: string): Buffer {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const count = readSync(descriptor, bytes, offset, size - offset, offset);
    if (count === 0) throw new Error(`Materialized corpus file shrank while it was read: ${path}`);
    offset += count;
  }
  const extra = Buffer.alloc(1);
  if (readSync(descriptor, extra, 0, 1, size) !== 0) {
    throw new Error(`Materialized corpus file grew while it was read: ${path}`);
  }
  return bytes;
}

function assertOpenedFileIdentity(path: string, opened: BigIntStats, expected: BigIntStats): void {
  if (opened.dev !== expected.dev || opened.ino !== expected.ino || !opened.isFile()) {
    throw new Error(`Materialized corpus entry changed while it was read: ${path}`);
  }
}

function readlinkNoFollow(path: string, before: BigIntStats): string {
  const target = decodeCorpusUtf8(
    readlinkSync(path, { encoding: "buffer" }),
    "materialized symlink target",
  );
  const after = lstatSync(path, { bigint: true });
  assertSymlinkIdentity(path, before, after);
  return target;
}

function assertSymlinkIdentity(path: string, before: BigIntStats, after: BigIntStats): void {
  if (before.dev !== after.dev || before.ino !== after.ino || !after.isSymbolicLink()) {
    throw new Error(`Materialized symlink changed while it was read: ${path}`);
  }
}

function walkDirectory(
  root: string,
  relativeDirectory: string,
  visit: (absolutePath: string, relativePath: string, metadata: BigIntStats) => void,
): void {
  const absoluteDirectory = relativeDirectory.length === 0 ? root : join(root, relativeDirectory);
  const names = readdirSync(absoluteDirectory, { encoding: "buffer" });
  for (const nameBytes of names) walkEntry(root, relativeDirectory, nameBytes, visit);
}

function walkEntry(
  root: string,
  relativeDirectory: string,
  nameBytes: Buffer,
  visit: (absolutePath: string, relativePath: string, metadata: BigIntStats) => void,
): void {
  const name = decodeCorpusUtf8(nameBytes, "materialized path");
  assertSafeObservedName(name);
  const relativePath = relativeDirectory.length === 0 ? name : `${relativeDirectory}/${name}`;
  const absolutePath = join(root, relativePath);
  const metadata = lstatSync(absolutePath, { bigint: true });
  visit(absolutePath, relativePath, metadata);
  if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
    walkDirectory(root, relativePath, visit);
  }
}

function assertSafeObservedName(name: string): void {
  if (name === "." || name === ".." || name.includes("/") || name.includes("\\")) {
    throw new Error(
      `Materialized corpus contains an unsafe path component: ${JSON.stringify(name)}`,
    );
  }
}

function assertBaselineEntries(current: CorpusManifest, baseline: CorpusManifest): void {
  for (const [path, expected] of baseline) {
    const actual = current.get(path);
    if (!actual || !sameManifestEntry(actual, expected)) {
      throw new Error(`Materialized benchmark source changed during the scan: ${path}`);
    }
  }
}

function assertOnlyKuzushiExtras(current: CorpusManifest, baseline: CorpusManifest): void {
  for (const path of current.keys()) assertAllowedExtra(path, baseline);
}

function assertAllowedExtra(path: string, baseline: CorpusManifest): void {
  if (baseline.has(path)) return;
  if (!isKuzushiStatePath(path)) {
    throw new Error(`Benchmark scan created state outside .kuzushi: ${path}`);
  }
}

function sameManifestEntry(left: ManifestEntry, right: ManifestEntry): boolean {
  return (
    left.type === right.type &&
    left.mode === right.mode &&
    left.size === right.size &&
    left.digest === right.digest &&
    left.target === right.target
  );
}
