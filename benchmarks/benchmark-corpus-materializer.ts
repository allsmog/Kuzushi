import {
  chmodSync,
  closeSync,
  constants,
  mkdirSync,
  openSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join, posix, win32 } from "node:path";
import {
  CORPUS_LIMITS,
  decodeCorpusUtf8,
  isKuzushiStatePath,
  type MaterializedTreeEntry,
} from "./benchmark-corpus-contract.js";

const MAX_SYMLINK_RESOLUTIONS = 64;
const WINDOWS_DRIVE_PREFIX = /^[a-z]:/iu;

interface CorpusPathIndex {
  types: Map<string, "directory" | "file" | "symlink">;
  targets: Map<string, string>;
}

export function materializeCorpusTree(root: string, entries: MaterializedTreeEntry[]): void {
  const directories = inferredDirectories(entries);
  for (const directory of directories) mkdirSync(join(root, directory), { mode: 0o700 });
  for (const entry of entries) materializeEntry(root, entry);
  makeSourceDirectoriesReadOnly(root, directories);
  assertSymlinkChainsStayInside(entries, directories);
}

/** Leave the corpus read-only while reserving one writable state directory. */
export function prepareKuzushiStateRoot(root: string, entries: MaterializedTreeEntry[]): void {
  if (!hasTrackedKuzushiRoot(entries)) mkdirSync(join(root, ".kuzushi"), { mode: 0o700 });
  chmodSync(root, 0o555);
}

function hasTrackedKuzushiRoot(entries: MaterializedTreeEntry[]): boolean {
  return entries.some((entry) => isKuzushiStatePath(entry.path));
}

function inferredDirectories(entries: MaterializedTreeEntry[]): string[] {
  const directories = new Set<string>();
  for (const entry of entries) addParentDirectories(entry.path, directories);
  return [...directories].sort(compareDirectories);
}

function addParentDirectories(path: string, directories: Set<string>): void {
  let parent = posix.dirname(path);
  while (parent !== ".") {
    directories.add(parent);
    parent = posix.dirname(parent);
  }
}

function compareDirectories(left: string, right: string): number {
  return pathDepth(left) - pathDepth(right) || left.localeCompare(right);
}

function pathDepth(path: string): number {
  return path.split("/").length;
}

function materializeEntry(root: string, entry: MaterializedTreeEntry): void {
  const destination = join(root, entry.path);
  if (entry.mode === "120000") {
    materializeSymlink(destination, entry);
    return;
  }
  materializeFile(destination, entry);
}

function materializeSymlink(destination: string, entry: MaterializedTreeEntry): void {
  const target = decodeCorpusUtf8(entry.bytes, `symlink target for ${entry.path}`);
  assertSafeSymlinkTarget(entry.path, target, entry.bytes.length);
  symlinkSync(target, destination);
}

function materializeFile(destination: string, entry: MaterializedTreeEntry): void {
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
  const descriptor = openSync(destination, flags, 0o600);
  try {
    writeFileSync(descriptor, entry.bytes);
  } finally {
    closeSync(descriptor);
  }
  chmodSync(destination, entry.mode === "100755" ? 0o555 : 0o444);
}

function assertSafeSymlinkTarget(path: string, target: string, targetBytes: number): void {
  assertSymlinkTargetSize(path, target, targetBytes);
  assertPortableSymlinkTarget(path, target);
  assertLexicalSymlinkTarget(path, target);
}

function assertSymlinkTargetSize(path: string, target: string, targetBytes: number): void {
  const invalidSize = targetBytes === 0 || targetBytes > CORPUS_LIMITS.symlinkTargetBytes;
  if (invalidSize || target.includes("\0")) {
    throw new Error(`Benchmark symlink ${path} has an invalid target size`);
  }
}

function assertPortableSymlinkTarget(path: string, target: string): void {
  const absolute = posix.isAbsolute(target) || win32.isAbsolute(target);
  if (target.includes("\\") || absolute || WINDOWS_DRIVE_PREFIX.test(target)) {
    throw new Error(`Benchmark symlink ${path} has an unsafe target`);
  }
}

function assertLexicalSymlinkTarget(path: string, target: string): void {
  const resolvedTarget = posix.normalize(posix.join(posix.dirname(path), target));
  if (resolvedTarget === ".." || resolvedTarget.startsWith("../")) {
    throw new Error(`Benchmark symlink ${path} escapes the materialized corpus`);
  }
}

function makeSourceDirectoriesReadOnly(root: string, directories: string[]): void {
  for (const directory of [...directories].reverse()) {
    chmodSync(join(root, directory), isKuzushiStatePath(directory) ? 0o700 : 0o555);
  }
  chmodSync(root, 0o700);
}

function assertSymlinkChainsStayInside(
  entries: MaterializedTreeEntry[],
  directories: string[],
): void {
  const index = corpusPathIndex(entries, directories);
  for (const entry of entries) {
    if (entry.mode === "120000") resolveSymlinkPath(entry.path, index);
  }
}

function corpusPathIndex(entries: MaterializedTreeEntry[], directories: string[]): CorpusPathIndex {
  const types = new Map<string, "directory" | "file" | "symlink">();
  const targets = new Map<string, string>();
  for (const directory of directories) types.set(directory, "directory");
  for (const entry of entries) addIndexedEntry(entry, types, targets);
  return { types, targets };
}

function addIndexedEntry(
  entry: MaterializedTreeEntry,
  types: CorpusPathIndex["types"],
  targets: CorpusPathIndex["targets"],
): void {
  if (entry.mode === "120000") {
    types.set(entry.path, "symlink");
    targets.set(entry.path, decodeCorpusUtf8(entry.bytes, `symlink target for ${entry.path}`));
    return;
  }
  types.set(entry.path, "file");
}

function resolveSymlinkPath(path: string, index: CorpusPathIndex): void {
  const pending = path.split("/");
  const resolved: string[] = [];
  const state = { traversals: 0 };
  while (pending.length > 0) {
    resolveNextComponent(path, pending, resolved, index, state);
  }
}

function resolveNextComponent(
  origin: string,
  pending: string[],
  resolved: string[],
  index: CorpusPathIndex,
  state: { traversals: number },
): void {
  const component = pending.shift()!;
  if (component.length === 0 || component === ".") return;
  if (component === "..") {
    popResolvedComponent(origin, resolved);
    return;
  }
  resolveNamedComponent(origin, component, pending, resolved, index, state);
}

function popResolvedComponent(origin: string, resolved: string[]): void {
  if (resolved.length === 0) {
    throw new Error(`Benchmark symlink ${origin} resolves outside the materialized corpus`);
  }
  resolved.pop();
}

function resolveNamedComponent(
  origin: string,
  component: string,
  pending: string[],
  resolved: string[],
  index: CorpusPathIndex,
  state: { traversals: number },
): void {
  const candidate = [...resolved, component].join("/");
  const type = index.types.get(candidate);
  if (!type) throw new Error(`Benchmark symlink ${origin} is dangling`);
  if (type === "symlink") {
    expandSymlink(origin, candidate, pending, index, state);
    return;
  }
  if (type === "file" && pending.length > 0) {
    throw new Error(`Benchmark symlink ${origin} traverses through a file`);
  }
  resolved.push(component);
}

function expandSymlink(
  origin: string,
  candidate: string,
  pending: string[],
  index: CorpusPathIndex,
  state: { traversals: number },
): void {
  state.traversals += 1;
  if (state.traversals > MAX_SYMLINK_RESOLUTIONS) {
    throw new Error(`Benchmark symlink ${origin} is cyclic or excessively deep`);
  }
  pending.unshift(...index.targets.get(candidate)!.split("/"));
}
