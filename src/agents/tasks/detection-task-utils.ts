/**
 * Shared utilities for detection task files.
 *
 * Extracted from 15+ detection task files that all duplicated these
 * functions character-for-character. Centralising them here reduces
 * maintenance burden and guarantees consistent behaviour.
 */

import { createHash } from "node:crypto";
import path from "node:path";
import type { Finding } from "../../scanners/types.js";
import { toErrorMessage } from "../../utils.js";
import type { TaskContext } from "../types.js";
import { resolveTaskAllowedTools, resolveTaskRuntime } from "./runtime-overrides.js";

// ── File-path normalisation ────────────────────────────────────────

/**
 * Convert an absolute `filePath` inside `repoRoot` to a relative one.
 * Returns the original path if it is already relative, falls outside
 * the repo root, or if the relative form would be empty.
 */
export function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

// ── Fingerprinting ─────────────────────────────────────────────────

/**
 * Compute a SHA-256 hex fingerprint from the given parts joined by `|`.
 * Used by every detection task to produce stable, deterministic
 * finding fingerprints.
 */
export function computeDetectionFingerprint(parts: string[]): string {
  return createHash("sha256").update(parts.join("|")).digest("hex");
}

// ── JSON parsing ───────────────────────────────────────────────────

/**
 * Thin wrapper around `JSON.parse` that converts parse errors into a
 * tagged `Error` so the caller can identify which task produced the
 * invalid output.
 */
export function parseJson(text: string, tag: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${tag} Invalid JSON output: ${toErrorMessage(error)}`);
  }
}

// ── Finding dedup + rank ───────────────────────────────────────────

/**
 * Deduplicate findings by fingerprint (keeping the highest score),
 * sort descending by score, and limit to `maxFindings`.
 */
export function dedupAndRankFindings(findings: Finding[], maxFindings: number): Finding[] {
  const deduped = new Map<string, Finding>();
  for (const f of findings) {
    const existing = deduped.get(f.fingerprint);
    if (!existing || f.score > existing.score) {
      deduped.set(f.fingerprint, f);
    }
  }
  return [...deduped.values()].sort((a, b) => b.score - a.score).slice(0, maxFindings);
}

// ── Lens runner ────────────────────────────────────────────────────

/**
 * Result of running a single analysis lens (a focused prompt against
 * the agent runtime).
 */
export interface LensResult {
  output: unknown;
  costUsd: number;
}

/**
 * Run a single analysis lens against the agent runtime and return the
 * structured output + cost. Shared by SSRF, NoSQL, template-injection,
 * and sharp-edges detection tasks.
 *
 * The caller supplies the task-specific JSON schema to use for
 * structured output validation.
 */
export async function runLens(
  prompt: string,
  context: TaskContext,
  model: string,
  tag: string,
  schema: Record<string, unknown>,
): Promise<LensResult> {
  const runtime = resolveTaskRuntime(context);
  let structuredOutput: unknown;
  let resultText = "";
  let costUsd = 0;

  for await (const message of runtime.query({
    prompt,
    options: {
      cwd: context.repoRoot,
      model,
      allowedTools: resolveTaskAllowedTools(context),
      permissionMode: "dontAsk",
      outputFormat: {
        type: "json_schema",
        schema,
        strict: true,
        retryInvalidStructuredOutput: 1,
      },
    },
  })) {
    if (message.type !== "result") continue;
    if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
      costUsd = message.totalCostUsd;
    }
    if ("result" in message) {
      resultText = message.result;
      structuredOutput = message.structuredOutput;
    } else if ("errors" in message) {
      throw new Error(
        `${tag} runtime error: ${(message as { errors: string[] }).errors?.join("; ") ?? "unknown"}`,
      );
    }
  }

  if (structuredOutput === undefined && resultText === "") {
    throw new Error(`${tag} runtime returned no output`);
  }
  return { output: structuredOutput ?? parseJson(resultText, tag), costUsd };
}
