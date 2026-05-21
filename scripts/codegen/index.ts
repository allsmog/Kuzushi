/**
 * Codegen orchestrator.
 *
 * Runs every registered generator in `scripts/codegen/generators/` and
 * writes its output under `generated/`.
 *
 * Contract for a generator:
 *
 *   interface Generator {
 *     name: string;                     // stable identifier (no spaces)
 *     description: string;              // human-readable one-liner
 *     run(outDir: string): Promise<void>; // write files under outDir
 *   }
 *
 *   export default generator satisfies Generator;
 *
 * Everything a generator writes MUST be deterministic (same inputs ->
 * byte-identical outputs). `pnpm codegen:check` re-runs every generator
 * into a temp dir and diffs the result against what's committed, so any
 * non-determinism (timestamps, random IDs, unsorted Object.keys, locale-
 * dependent formatting, etc.) will fail CI.
 *
 * See `docs/devex/04-codegen-assessment.md` for the mental model and the
 * bar for adding a new generator.
 */
import { mkdir, rm } from "node:fs/promises";
import { resolve } from "node:path";
// Registered generators. Add new ones here in alphabetical order.
import configJsonSchema from "./generators/config-json-schema.js";
import llmIoJsonSchemas from "./generators/llm-io-json-schemas.js";
import type { Generator } from "./types.js";

const generators: Generator[] = [configJsonSchema, llmIoJsonSchemas];

const REPO_ROOT = resolve(new URL(".", import.meta.url).pathname, "../..");
const DEFAULT_OUT_DIR = resolve(REPO_ROOT, "generated");

export interface RunOptions {
  /** Directory to write generated output to. Defaults to `<repo>/generated`. */
  outDir?: string;
  /** If true, wipe outDir before running. Used by codegen:check. */
  clean?: boolean;
  /** If true, stay silent on stdout. */
  quiet?: boolean;
}

export async function runCodegen(options: RunOptions = {}): Promise<{
  outDir: string;
  ran: string[];
}> {
  const outDir = options.outDir ?? DEFAULT_OUT_DIR;
  const log = codegenLogger(options.quiet ?? false);

  if (options.clean) {
    await rm(outDir, { recursive: true, force: true });
  }
  await mkdir(outDir, { recursive: true });

  if (generators.length === 0) {
    log("[codegen] no generators registered yet");
    return { outDir, ran: [] };
  }

  const ran: string[] = [];
  for (const gen of generators) {
    log(`[codegen] running ${gen.name} — ${gen.description}`);
    await gen.run(outDir);
    ran.push(gen.name);
  }

  log(`[codegen] wrote output to ${outDir}`);
  return { outDir, ran };
}

function codegenLogger(quiet: boolean): (msg: string) => void {
  if (quiet) return () => {};
  return (msg: string): void => {
    process.stdout.write(`${msg}\n`);
  };
}

// Allow `tsx scripts/codegen/index.ts` invocation.
const isMain =
  import.meta.url === `file://${process.argv[1]}` ||
  import.meta.url.endsWith(process.argv[1] ?? "");
if (isMain) {
  runCodegen().catch((err: unknown) => {
    const msg = err instanceof Error ? (err.stack ?? err.message) : String(err);
    process.stderr.write(`[codegen] failed: ${msg}\n`);
    process.exit(1);
  });
}
