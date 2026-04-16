/**
 * Drift detector: re-runs every generator into a temp dir and compares the
 * result against the `generated/` tree that's committed. Exits non-zero if
 * any file differs, is missing, or is extra.
 *
 * Designed to run in CI after `pnpm install` with no side effects to the
 * working tree.
 */
import { mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";

import { runCodegen } from "./index.js";

const REPO_ROOT = resolve(new URL(".", import.meta.url).pathname, "../..");
const COMMITTED_DIR = resolve(REPO_ROOT, "generated");

interface DiffEntry {
  relPath: string;
  kind: "missing" | "extra" | "changed";
  detail?: string;
}

async function walk(root: string): Promise<Map<string, Buffer>> {
  const out = new Map<string, Buffer>();
  async function rec(dir: string): Promise<void> {
    let entries: Array<{ name: string; isDirectory: () => boolean }>;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
      throw err;
    }
    for (const ent of entries) {
      const full = join(dir, ent.name);
      if (ent.isDirectory()) {
        await rec(full);
      } else {
        // Skip README — it's hand-written documentation, not generated.
        const rel = relative(root, full).split(sep).join("/");
        if (rel === "README.md") continue;
        const buf = await readFile(full);
        out.set(rel, buf);
      }
    }
  }
  await rec(root);
  return out;
}

async function main(): Promise<void> {
  const exists = await stat(COMMITTED_DIR)
    .then(() => true)
    .catch(() => false);
  if (!exists) {
    process.stderr.write(
      `[codegen:check] ${COMMITTED_DIR} does not exist — run \`pnpm codegen\` and commit the output.\n`,
    );
    process.exit(1);
  }

  const tmpRoot = await mkdtemp(join(tmpdir(), "kuzushi-codegen-check-"));
  try {
    await runCodegen({ outDir: tmpRoot, clean: true, quiet: true });

    const committed = await walk(COMMITTED_DIR);
    const fresh = await walk(tmpRoot);

    const diffs: DiffEntry[] = [];

    for (const [rel, buf] of fresh) {
      const have = committed.get(rel);
      if (!have) {
        diffs.push({ relPath: rel, kind: "missing" });
      } else if (!have.equals(buf)) {
        diffs.push({
          relPath: rel,
          kind: "changed",
          detail: `committed=${have.byteLength}B, regenerated=${buf.byteLength}B`,
        });
      }
    }
    for (const rel of committed.keys()) {
      if (!fresh.has(rel)) {
        diffs.push({ relPath: rel, kind: "extra" });
      }
    }

    if (diffs.length === 0) {
      process.stdout.write("[codegen:check] OK — no drift\n");
      return;
    }

    process.stderr.write("[codegen:check] DRIFT DETECTED:\n");
    for (const d of diffs) {
      const reason =
        d.kind === "missing"
          ? "would be added by `pnpm codegen` but is not committed"
          : d.kind === "extra"
            ? "is committed but no generator produces it"
            : `differs from 'pnpm codegen' output (${d.detail ?? "content mismatch"})`;
      process.stderr.write(`  - ${d.relPath}: ${reason}\n`);
    }
    process.stderr.write(
      "\nRun `pnpm codegen` locally, commit the updated files under `generated/`, and push.\n",
    );
    process.exit(1);
  } finally {
    await rm(tmpRoot, { recursive: true, force: true });
  }
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? (err.stack ?? err.message) : String(err);
  process.stderr.write(`[codegen:check] failed: ${msg}\n`);
  process.exit(1);
});
