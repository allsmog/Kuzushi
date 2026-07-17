import {
  type BigIntStats,
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  rmdirSync,
  unlinkSync,
} from "node:fs";
import type { CorpusIdentity } from "./benchmark-corpus-contract.js";

type NativePath = Buffer;

export function corpusRootIdentity(path: string): CorpusIdentity {
  const metadata = lstatSync(path, { bigint: true });
  assertDirectory(path, metadata);
  return { dev: metadata.dev, ino: metadata.ino };
}

export function assertCorpusRootIdentity(root: string, expected: CorpusIdentity): void {
  const actual = corpusRootIdentity(root);
  if (actual.dev !== expected.dev || actual.ino !== expected.ino) {
    throw new Error("Materialized corpus root identity changed during the benchmark");
  }
}

export function cleanupCorpus(root: string, identity: CorpusIdentity): void {
  assertCorpusRootIdentity(root, identity);
  const nativeRoot = Buffer.from(root);
  restoreWritableModes(nativeRoot);
  removeTreeNoFollow(nativeRoot);
}

function assertDirectory(path: string, metadata: BigIntStats): void {
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`Materialized corpus root is not a directory: ${path}`);
  }
}

function restoreWritableModes(path: NativePath): void {
  const metadata = lstatSync(path, { bigint: true });
  if (metadata.isSymbolicLink()) return;
  restoreWritableEntry(path, metadata);
}

function restoreWritableEntry(path: NativePath, metadata: BigIntStats): void {
  if (metadata.isDirectory()) {
    restoreWritableDirectory(path, metadata);
    return;
  }
  if (metadata.isFile()) chmodNoFollow(path, metadata, 0o600);
}

function restoreWritableDirectory(path: NativePath, metadata: BigIntStats): void {
  chmodNoFollow(path, metadata, 0o700);
  for (const name of readdirSync(path, { encoding: "buffer" })) {
    restoreWritableModes(childPath(path, name));
  }
}

function chmodNoFollow(path: NativePath, expected: BigIntStats, mode: number): void {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    assertOpenedIdentity(opened, expected);
    fchmodSync(descriptor, mode);
  } finally {
    closeSync(descriptor);
  }
}

function assertOpenedIdentity(opened: BigIntStats, expected: BigIntStats): void {
  if (opened.dev !== expected.dev || opened.ino !== expected.ino) {
    throw new Error("Materialized corpus entry changed during cleanup");
  }
}

function removeTreeNoFollow(path: NativePath): void {
  const metadata = lstatSync(path);
  if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
    removeDirectoryNoFollow(path);
    return;
  }
  unlinkSync(path);
}

function removeDirectoryNoFollow(path: NativePath): void {
  for (const name of readdirSync(path, { encoding: "buffer" })) {
    removeTreeNoFollow(childPath(path, name));
  }
  rmdirSync(path);
}

function childPath(parent: NativePath, name: Buffer): NativePath {
  return Buffer.concat([parent, Buffer.from("/"), name]);
}
