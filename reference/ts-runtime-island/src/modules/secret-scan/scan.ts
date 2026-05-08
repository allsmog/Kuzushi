/**
 * Pure scanning core for `secret-scan`.
 *
 * Lives in its own module so the tool wrapper (which talks to the
 * Kuzushi `ExecutionContext`) and the unit tests share the same engine.
 */

import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import type { Finding } from "../../scanners/types.js";
import {
  DEFAULT_DETECTORS,
  redactSecret,
  type SecretDetector,
  shannonEntropy,
} from "./detectors.js";

const DEFAULT_EXCLUDE_DIRS: ReadonlySet<string> = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  "vendor",
  "third_party",
  "third-party",
  "dist",
  "build",
  "out",
  ".next",
  ".nuxt",
  ".cache",
  ".turbo",
  "coverage",
  "__pycache__",
  ".venv",
  "venv",
  ".tox",
  "target",
]);

const DEFAULT_BINARY_EXTS: ReadonlySet<string> = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".bmp",
  ".ico",
  ".svg",
  ".pdf",
  ".zip",
  ".gz",
  ".tar",
  ".tgz",
  ".bz2",
  ".xz",
  ".7z",
  ".rar",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".bin",
  ".class",
  ".jar",
  ".war",
  ".pyc",
  ".pyo",
  ".o",
  ".a",
  ".node",
  ".wasm",
  ".woff",
  ".woff2",
  ".ttf",
  ".otf",
  ".eot",
  ".mp3",
  ".mp4",
  ".mov",
  ".avi",
  ".webm",
  ".lock",
]);

/** Public options accepted by `scanForSecrets`. */
export interface SecretScanOptions {
  /** Maximum file size in bytes; larger files are skipped. Default 2 MiB. */
  maxFileBytes?: number;
  /** Directories (basename match) to skip; merged with the default block-list. */
  excludeDirs?: ReadonlyArray<string>;
  /** Extensions (with leading dot) to treat as binary; merged with the defaults. */
  binaryExts?: ReadonlyArray<string>;
  /**
   * When provided, overrides the built-in detector pack. Useful for tests
   * and for operators who want to ship a custom rule pack via
   * `taskConfig["secret-scan"].detectors`.
   */
  detectors?: ReadonlyArray<SecretDetector>;
  /** Maximum findings to emit before bailing out. Default 1000. */
  maxFindings?: number;
}

export interface SecretScanResult {
  findings: Finding[];
  /** Number of files actually inspected (post-filter). */
  filesScanned: number;
  /** Number of files skipped because of the size cap or binary extension. */
  filesSkipped: number;
}

/**
 * Walk a directory and yield every regular file, applying the directory
 * block-list. Symlinks are not followed — keeps things deterministic and
 * avoids the cycle case.
 */
async function* walk(
  root: string,
  excludeDirs: ReadonlySet<string>,
): AsyncGenerator<string, void, unknown> {
  const stack: string[] = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    if (!dir) break;
    let entries: import("node:fs").Dirent[];
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (excludeDirs.has(entry.name)) continue;
        stack.push(full);
      } else if (entry.isFile()) {
        yield full;
      }
      // Skip symlinks, sockets, FIFOs.
    }
  }
}

function isLikelyBinary(buffer: Buffer): boolean {
  // A file with a NUL byte in the first 4 KiB is treated as binary.
  const sample = buffer.subarray(0, Math.min(buffer.length, 4096));
  for (let i = 0; i < sample.length; i++) {
    if (sample[i] === 0) return true;
  }
  return false;
}

function fingerprintFor(
  repoRoot: string,
  ruleId: string,
  filePath: string,
  line: number,
  match: string,
): string {
  const digest = createHash("sha256")
    .update(
      [path.basename(repoRoot), "secret-scan", ruleId, filePath, String(line), match].join("|"),
    )
    .digest("hex");
  return `secret-scan:${ruleId}:${digest.slice(0, 16)}`;
}

/**
 * Locate the byte/character offset of a regex match in `text` and return
 * the 1-indexed line number plus the matching line's text.
 */
function locateMatch(text: string, index: number): { line: number; lineText: string } {
  let line = 1;
  let lineStart = 0;
  for (let i = 0; i < index; i++) {
    if (text.charCodeAt(i) === 10) {
      line += 1;
      lineStart = i + 1;
    }
  }
  let lineEnd = text.indexOf("\n", lineStart);
  if (lineEnd === -1) lineEnd = text.length;
  return { line, lineText: text.slice(lineStart, lineEnd) };
}

/** Run every detector against `text`; return a list of (detector, match info). */
export function detectSecretsInText(
  text: string,
  detectors: ReadonlyArray<SecretDetector>,
): Array<{
  detector: SecretDetector;
  match: string;
  index: number;
  capturedSecret: string;
}> {
  const out: Array<{
    detector: SecretDetector;
    match: string;
    index: number;
    capturedSecret: string;
  }> = [];

  for (const detector of detectors) {
    // Defensive: ensure global flag so .exec loop terminates.
    const flags = detector.pattern.flags.includes("g")
      ? detector.pattern.flags
      : `${detector.pattern.flags}g`;
    const re = new RegExp(detector.pattern.source, flags);

    // Cap per-detector matches to prevent pathological inputs from blowing
    // up. 200 is far above any realistic per-file finding count.
    let perDetectorCount = 0;
    let m: RegExpExecArray | null = re.exec(text);
    while (m !== null) {
      if (perDetectorCount >= 200) break;
      perDetectorCount += 1;
      const captured = m[1] ?? m[0];
      const matched = m[0];
      if (
        detector.entropyThreshold !== undefined &&
        shannonEntropy(captured) < detector.entropyThreshold
      ) {
        // Avoid zero-length forever-loop on degenerate patterns.
        if (matched.length === 0) re.lastIndex += 1;
        m = re.exec(text);
        continue;
      }
      out.push({
        detector,
        match: matched,
        index: m.index,
        capturedSecret: captured,
      });
      if (matched.length === 0) re.lastIndex += 1;
      m = re.exec(text);
    }
  }

  return out;
}

/**
 * Run the secret scan over `repoRoot`. Returns a `SecretScanResult`.
 *
 * Pure: reads the filesystem, never the network. Honours the abort signal
 * so the caller can cancel a long scan from `ctx.signal`.
 */
export async function scanForSecrets(
  repoRoot: string,
  options: SecretScanOptions = {},
  signal?: AbortSignal,
): Promise<SecretScanResult> {
  const root = path.resolve(repoRoot);
  const stat = await fs.stat(root).catch(() => null);
  if (!stat || !stat.isDirectory()) {
    throw new Error(`secret-scan: target is not a directory: ${root}`);
  }

  const excludeDirs = new Set<string>([...DEFAULT_EXCLUDE_DIRS, ...(options.excludeDirs ?? [])]);
  const binaryExts = new Set<string>([...DEFAULT_BINARY_EXTS, ...(options.binaryExts ?? [])]);
  const maxFileBytes = options.maxFileBytes ?? 2 * 1024 * 1024;
  const detectors = options.detectors ?? DEFAULT_DETECTORS;
  const maxFindings = options.maxFindings ?? 1000;

  const findings: Finding[] = [];
  let filesScanned = 0;
  let filesSkipped = 0;

  outer: for await (const filePath of walk(root, excludeDirs)) {
    if (signal?.aborted) break;
    const ext = path.extname(filePath).toLowerCase();
    if (binaryExts.has(ext)) {
      filesSkipped += 1;
      continue;
    }
    let fileStat: import("node:fs").Stats;
    try {
      fileStat = await fs.stat(filePath);
    } catch {
      continue;
    }
    if (fileStat.size > maxFileBytes) {
      filesSkipped += 1;
      continue;
    }

    let buffer: Buffer;
    try {
      buffer = await fs.readFile(filePath);
    } catch {
      continue;
    }
    if (isLikelyBinary(buffer)) {
      filesSkipped += 1;
      continue;
    }
    filesScanned += 1;

    const text = buffer.toString("utf8");
    const hits = detectSecretsInText(text, detectors);
    for (const hit of hits) {
      const { line, lineText } = locateMatch(text, hit.index);
      const relPath = path.relative(root, filePath) || path.basename(filePath);
      const fingerprint = fingerprintFor(root, hit.detector.id, relPath, line, hit.match);
      const redacted = redactSecret(hit.capturedSecret);
      const severity = hit.detector.severity;
      const finding: Finding = {
        taskId: "secret-scan",
        fingerprint,
        ruleId: `secret-scan/${hit.detector.id}`,
        filePath: relPath,
        startLine: line,
        severity,
        message: `${hit.detector.name}: ${hit.detector.description}`,
        evidence: `${relPath}:${line}: ${lineText.replace(hit.capturedSecret, redacted).trim()}`,
        scannerConfidence: hit.detector.entropyThreshold !== undefined ? "MEDIUM" : "HIGH",
        subcategory: ["secret"],
        likelihood: severity === "ERROR" ? "HIGH" : "MEDIUM",
        impact: severity === "ERROR" ? "HIGH" : "MEDIUM",
        cwe: hit.detector.cwe ? [hit.detector.cwe] : ["CWE-798"],
        score: severity === "ERROR" ? 30 : severity === "WARNING" ? 20 : 10,
      };
      findings.push(finding);
      if (findings.length >= maxFindings) break outer;
    }
  }

  return { findings, filesScanned, filesSkipped };
}
