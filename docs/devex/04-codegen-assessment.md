# Codegen assessment

**Status:** Infrastructure in place. Three generators live. Bar for adding more is documented.

**Audience:** Future contributors wondering "should this be a generator?" and reviewers judging a PR that adds one.

---

## tl;dr

- Kuzushi had **no codegen** before this doc. The Zod schemas in [`src/schemas.ts`](../../src/schemas.ts) are the source of truth for core data shapes, and the 25 migration files in [`src/migrations/`](../../src/migrations/) are the source of truth for the SQLite schema.
- Hand-writing everything is the right default. Three narrow cases are now generated because *machines can project the Zod/migration truth into a stable external format for free*.
- Everything generated lives under [`generated/`](../../generated/) and is marked `linguist-generated=true` in [`.gitattributes`](../../.gitattributes) so PR diffs collapse and GitHub language stats ignore it.
- `pnpm codegen` regenerates. `pnpm codegen:check` fails if `generated/` drifts from source — wire it into CI so a bad merge cannot sneak stale artifacts in.

---

## What is generated today

| Path | Source of truth | Why generate |
| --- | --- | --- |
| `generated/schemas/kuzushi-config.json` | `KuzushiConfigSchema` in `src/schemas.ts` | Machine-readable config description. Useful for IDE JSON validation, external config editors, and the docs site. The Zod schema already exists; exposing it as JSON Schema is a free projection. |
| `generated/schemas/llm-io/raw-*.json` | `Raw{Triage,Verification,PocHarness}OutputSchema` in `src/schemas.ts` | These are the exact JSON shapes Kuzushi's agent prompts require from the LLM. Exporting JSON Schema lets prompt authors paste them into `response_format` / tool-use `input_schema`, and external consumers parse raw agent outputs against them. |
| `generated/db/schema.sql` | `src/migrations/*.ts` | Consolidated reference DDL for anyone browsing the repo. Produced by running every migration against an in-memory SQLite DB and dumping `sqlite_master`. Migrations remain the only thing production DBs execute against. |

None of these files are imported by runtime source under `src/`. They are pure external-facing artifacts. If you ever find yourself tempted to `import`/`require` from `generated/` inside `src/`, stop and think — it probably means the Zod schema should be the import target instead.

---

## The bar for adding a new generator

Add one if **all** of the following are true:

1. **There is a single source of truth that already exists** (a Zod schema, a migration, a config file). Generators are projections, not new information.
2. **Byte-identical re-runs are cheap.** If the generator depends on network, wall-clock time, environment, or non-deterministic hash maps, it cannot be drift-checked. Fix the determinism first or don't add it.
3. **A concrete consumer is asking.** "Might be useful someday" is not enough. Name the tool / person / downstream repo that reads the artifact.
4. **It cannot be a TypeScript `export` instead.** If the only consumer is our own codebase, a regular TS file importable from `src/` is simpler.

Concrete examples I considered and **rejected**:

| Candidate | Rejected because |
| --- | --- |
| OpenAPI for the SSE streaming endpoint (`src/streaming.ts`) | Endpoint is internal, single-consumer (the docs UI), trivial shape. Writing a tiny `.md` is cheaper than adopting `@asteasolutions/zod-to-openapi`. |
| SARIF schema | SARIF is defined externally by OASIS; we do not author it. We emit SARIF (in `src/report-sarif.ts`) — we don't generate its schema. |
| TypeScript types from Zod | Already handled by `z.infer<>` in `src/schemas.ts`. Adding codegen for this would be pure ceremony. |
| Compiled Ink help text | Small enough to live in `src/ui/` as a normal `.ts` module. No external consumer. |
| Bundled prompt library | Already lives in `src/prompts/**` with the prompts as normal TS strings. Bundling for external distribution is a packaging concern, not codegen. |

If a future candidate passes the four-point bar, adding it is ~30 lines (see "How to add a generator" below).

---

## How it fits together

```
 src/schemas.ts   ──┐                               ┌──► generated/schemas/kuzushi-config.json
                    │                               │
 src/schemas.ts   ──┼──► scripts/codegen/ ──────────┼──► generated/schemas/llm-io/*.json
 (LLM I/O types)    │     (index.ts runs every      │
                    │      generator in order)      │
 src/migrations/ ──┘                                └──► generated/db/schema.sql
```

Control flow:

1. `pnpm codegen` → `scripts/codegen/index.ts` imports each generator from `scripts/codegen/generators/` and calls `run(outDir)`.
2. Each generator writes deterministic files under `outDir`.
3. `pnpm codegen:check` → `scripts/codegen/check.ts` re-runs every generator into `os.tmpdir()`, walks both trees, and exits non-zero on any diff. Used in CI.

Determinism is guaranteed by:
- `scripts/codegen/util.ts`'s `formatJson()` — sorts object keys recursively and appends a single trailing newline so the same Zod schema always yields the same bytes.
- `db-schema-sql.ts` — queries `sqlite_master` with an explicit `ORDER BY` (type, table name, object name) and filters out internal `sqlite_*` objects.

---

## How to add a generator

1. Check the bar above. Don't skip this.
2. Create `scripts/codegen/generators/<name>.ts`:

   ```ts
   import { mkdir, writeFile } from "node:fs/promises";
   import { join } from "node:path";
   import type { Generator } from "../types.js";

   const generator: Generator = {
     name: "<slug>",
     description: "one-line purpose",
     async run(outDir) {
       const dest = join(outDir, "<subdir>");
       await mkdir(dest, { recursive: true });
       // ...write deterministic files under dest...
     },
   };

   export default generator;
   ```

3. Register it in [`scripts/codegen/index.ts`](../../scripts/codegen/index.ts) (alphabetical order).
4. Run `pnpm codegen && pnpm codegen:check` locally. The second command must pass on a clean checkout.
5. Commit both the generator *and* its output under `generated/`. The first run of CI's drift check will either agree or immediately catch your non-determinism.
6. If the output is JSON, use `formatJson()` from `scripts/codegen/util.ts`. If it's any other text format, convince yourself it's byte-stable across Node versions and runs.
7. Update the table at the top of this doc so the purpose is recorded.

---

## Why this shape and not others

- **Single `generated/` directory, not scattered `*.generated.ts` files.** Collapsing everything under one subtree means `.gitattributes` can flag it with two lines, reviewers can mentally skip it, and the codegen command has exactly one output contract.
- **JSON, not TS.** We don't emit `.ts` files that need to be imported, because anything importable should live in `src/` as hand-written TypeScript. `generated/` is strictly for non-TS consumers.
- **Committed, not built on the fly.** Committing the output makes drift visible in PR review, keeps `npm install` fast (no post-install codegen step), and means doc tooling can link to stable URLs inside the repo. The cost is that contributors need to remember to run `pnpm codegen` — which `pnpm codegen:check` in CI enforces.
- **No third-party codegen dependency.** Zod 4 ships `z.toJSONSchema()` natively. `better-sqlite3` is already a dependency. The codegen system adds **zero** new npm packages.

---

## Followups

- [ ] **DX-2:** add `pnpm codegen:check` to `.github/workflows/ci.yml` so drift blocks merges. Single line in the main CI job, no new workflow needed.
- [ ] **DX-3:** optionally include `scripts/codegen/tsconfig.json` in `scripts/typecheck-all.mjs` so `pnpm check:types` catches broken generator code. Today it is only validated at runtime by `tsx` — `pnpm typecheck:codegen` is wired up but standalone.
- [ ] Revisit whether the generated JSON schemas should be published somewhere discoverable (GitHub Pages? npm?) once there is a concrete external consumer. Currently they are "available to anyone who clones the repo."

---

## Appendix: commands

| Command | Purpose |
| --- | --- |
| `pnpm codegen` | Rewrite every file under `generated/`. Idempotent. |
| `pnpm codegen:check` | CI: exit 1 if `generated/` is out of sync with the generators' output. |
| `pnpm typecheck:codegen` | Run `tsc --noEmit` against `scripts/codegen/` and its `src/` imports. |
