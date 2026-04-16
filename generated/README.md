# `generated/`

Everything in this directory is **machine-generated**. Do not hand-edit.

## Regenerate

```bash
pnpm codegen          # rewrite every file under generated/
pnpm codegen:check    # CI: fail if generated/ is out of sync with source
```

Both commands are implemented in [`scripts/codegen/`](../scripts/codegen/).
The generator registry lives in [`scripts/codegen/index.ts`](../scripts/codegen/index.ts).

## What lives here

| Subdir        | Source of truth                 | Purpose                                              |
| ------------- | ------------------------------- | ---------------------------------------------------- |
| `schemas/`    | `src/schemas.ts` (Zod)          | JSON Schema projections for external tooling         |
| `schemas/llm-io/` | `src/schemas.ts` (Zod)      | Raw LLM I/O contracts (triage / verify / poc harness) |
| `db/`         | `src/migrations/`               | Consolidated SQLite `schema.sql` reference dump      |

## Why these files are committed

- **Diff review:** generated drift shows up in PRs, so reviewers can spot
  unintended contract changes at the same time they review the Zod / migration
  edit that caused them.
- **Release artifacts:** npm consumers and doc tooling can point at a stable
  URL in the repo.
- **CI drift detection:** `pnpm codegen:check` refuses to pass if the
  committed tree disagrees with what the generators would produce today.

## Ignored by reviewers

This directory is flagged `linguist-generated=true` in [`.gitattributes`](../.gitattributes),
which:

- Excludes it from GitHub language stats.
- Collapses diffs by default in GitHub's web UI (they still review, just
  hidden-by-default).

## Adding a new generator

See [`docs/devex/04-codegen-assessment.md`](../docs/devex/04-codegen-assessment.md) —
there is an explicit bar for when codegen is warranted and a step-by-step
guide for registering a new generator.
