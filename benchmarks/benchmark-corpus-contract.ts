export const CORPUS_LIMITS = {
  gitTimeoutMs: 120_000,
  treeOutputBytes: 32 * 1024 * 1024,
  entryCount: 100_000,
  pathBytes: 4_096,
  totalPathBytes: 16 * 1024 * 1024,
  blobBytes: 64 * 1024 * 1024,
  totalBlobBytes: 512 * 1024 * 1024,
  symlinkCount: 4_096,
  symlinkTargetBytes: 4_096,
  batchProtocolOverheadBytes: 16 * 1024 * 1024,
} as const;

export interface MaterializedTreeEntry {
  mode: "100644" | "100755" | "120000";
  objectId: string;
  path: string;
  size: number;
  bytes: Buffer;
}

export interface CorpusIdentity {
  dev: bigint;
  ino: bigint;
}

export interface ManifestEntry {
  type: "directory" | "file" | "symlink";
  mode: number;
  size: number;
  digest?: string;
  target?: string;
}

export type CorpusManifest = Map<string, ManifestEntry>;

const utf8 = new TextDecoder("utf-8", { fatal: true });

export function decodeCorpusUtf8(bytes: Uint8Array, label: string): string {
  try {
    return utf8.decode(bytes);
  } catch {
    throw new Error(`Benchmark ${label} is not valid UTF-8`);
  }
}

export function checkedCorpusTotal(
  current: number,
  addition: number,
  maximum: number,
  label: string,
): number {
  const total = current + addition;
  if (!Number.isSafeInteger(total) || total > maximum) {
    throw new Error(`Benchmark commit exceeds ${maximum} total ${label}`);
  }
  return total;
}

export function isKuzushiStatePath(path: string): boolean {
  return path === ".kuzushi" || path.startsWith(".kuzushi/");
}
