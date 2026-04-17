/**
 * Crash triage helpers — enumerate crash artifacts on disk, normalize their
 * content into `CrashArtifact` records, and dedupe by stack hash (or file
 * content hash when no stack is available).
 *
 * Keeping this pure-functional and filesystem-only means it's easy to test
 * and cheap to run BEFORE any LLM call — which is what the fuzz-forge plan
 * demands (minimize first, then triage).
 */

import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

export interface CrashArtifact {
  /** Absolute path to the crash input file. */
  path: string;
  /** Size in bytes. */
  sizeBytes: number;
  /** Hex digest of the crash input content. */
  contentHash: string;
  /** When available (from an accompanying stack trace), a stack digest. */
  stackHash?: string;
  /** Stack trace text, when discovered. */
  stackTrace?: string;
  /** Signature line most likely to classify the crash (for display). */
  signature?: string;
}

const CRASH_FILE_PATTERNS = [
  /^crash-/i,
  /^id:\d+/i,
  /^SIGSEGV/i,
  /^SIGABRT/i,
  /^oom-/i,
  /^leak-/i,
  /^timeout-/i,
  /^slow-unit-/i,
];

// Sidecar files (stack traces, raw stderr) live alongside the actual crash
// input. Exclude them from enumeration so `describeCrash` can read them as
// context for their companion crash file.
const SIDECAR_EXTENSIONS = [".log", ".stacktrace", ".stderr", ".crash"];

function isCrashFilename(name: string): boolean {
  if (SIDECAR_EXTENSIONS.some((ext) => name.toLowerCase().endsWith(ext))) return false;
  return CRASH_FILE_PATTERNS.some((re) => re.test(name));
}

function hashBuffer(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

function sanitizeStackFrames(stack: string): string[] {
  const frames: string[] = [];
  for (const rawLine of stack.split(/\r?\n/)) {
    const line = rawLine.trim();
    // libFuzzer/ASan frames look like: `    #3 0x... in function_name path/to/file.c:42:3`
    const m = line.match(/^#\d+\s+0x[0-9a-f]+\s+in\s+([^\s]+)/i);
    if (m) {
      frames.push(m[1]!);
      continue;
    }
    // Go panic stacks: `\tgoroutine 1 [running]:\nmain.Parse(...)`
    const goMatch = line.match(/^([\w./-]+)\(\.\.\.\)?$/);
    if (goMatch) frames.push(goMatch[1]!);
  }
  return frames;
}

function computeStackHash(frames: string[]): string | undefined {
  if (frames.length === 0) return undefined;
  // Use the top 5 frames (attack-surface depth is usually small enough
  // for dedup to be meaningful beyond that).
  const top = frames.slice(0, 5);
  return createHash("sha256").update(top.join("|")).digest("hex");
}

function extractSignature(stack: string): string | undefined {
  for (const line of stack.split(/\r?\n/)) {
    if (/==ERROR:|== SUMMARY:|==ERROR|runtime error:|panic:/i.test(line)) {
      return line.trim();
    }
  }
  return undefined;
}

/**
 * Build a `CrashArtifact` from a path to a crash input. If a sibling file
 * named `<input>.log`, `<input>.stacktrace`, or `<input>.stderr` exists,
 * use its contents as the stack trace.
 */
export function describeCrash(crashPath: string): CrashArtifact {
  const buf = readFileSync(crashPath);
  const contentHash = hashBuffer(buf);
  let stackTrace: string | undefined;

  for (const ext of [".log", ".stacktrace", ".stderr", ".crash"]) {
    const candidate = `${crashPath}${ext}`;
    try {
      stackTrace = readFileSync(candidate, "utf8");
      break;
    } catch {
      /* not present */
    }
  }

  const frames = stackTrace ? sanitizeStackFrames(stackTrace) : [];
  const stackHash = computeStackHash(frames);
  const signature = stackTrace ? extractSignature(stackTrace) : undefined;

  return {
    path: crashPath,
    sizeBytes: buf.length,
    contentHash,
    stackHash,
    stackTrace,
    signature,
  };
}

/**
 * Enumerate crashes in a directory. Recurses one level (libFuzzer writes
 * flat; AFL++ nests under `default/crashes/`).
 */
export function findCrashFiles(crashDir: string): string[] {
  const out: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(crashDir);
  } catch {
    return [];
  }
  for (const name of entries) {
    const full = path.join(crashDir, name);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      continue;
    }
    if (stat.isDirectory()) {
      for (const child of findCrashFiles(full)) out.push(child);
      continue;
    }
    if (!isCrashFilename(name)) continue;
    out.push(full);
  }
  return out;
}

/**
 * Collect + dedupe crashes in a directory. Duplicates are coalesced by
 * stack hash when available, else by content hash.
 */
export function collectUniqueCrashes(crashDir: string): CrashArtifact[] {
  const all = findCrashFiles(crashDir).map(describeCrash);
  const byKey = new Map<string, CrashArtifact>();
  for (const crash of all) {
    const key = crash.stackHash ?? crash.contentHash;
    if (!byKey.has(key)) byKey.set(key, crash);
  }
  return [...byKey.values()].sort((a, b) => a.sizeBytes - b.sizeBytes);
}

export const __crashInternals = {
  CRASH_FILE_PATTERNS,
  isCrashFilename,
  sanitizeStackFrames,
  computeStackHash,
  extractSignature,
};
