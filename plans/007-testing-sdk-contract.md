# Plan 007: Harden the published TypeScript SDK contract and remove unused SQLite

> **Status: superseded historical plan.** The TypeScript SDK and its package
> exports were retired by the Rust/KWP cutover. Do not execute this plan; use
> `docs/modules.md` for the current third-party module contract.
>
> Historical executor instruction: preserve the `kuzushi/testing` and
> `kuzushi/modules` public exports. This instruction is no longer operative.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Category**: dependency/tests
- **Planned at**: commit `775a4134f2cb`, 2026-07-12

## Why this matters

The published testing helpers have no behavior suite and coverage excludes
untouched files. The npm package also installs/rebuilds `better-sqlite3` even
though production code imports it only as a type for optional `DagContext.db`.

## Current state

- `package.json` exports `./testing`; `src/testing/index.ts` supplies context
  mocks and recording adapters.
- `vitest.config.ts` excludes unimported files from coverage.
- `src/modules/types.ts` type-imports `better-sqlite3` solely for optional
  `DagContext.db`.
- `scripts/check-native-bindings.mjs` and `scripts/verify-pack.mjs` make the
  addon part of install/pack verification.

## Steps

1. Add `tests/testing/public-surface.test.ts` covering every exported helper,
   override precedence, recorder ordering, error behavior, and compatible
   module/context shapes.
2. Add a dedicated coverage include/threshold for `src/testing/**` or enable
   all-file coverage with explicit justified exclusions. Tests must fail if the
   published helper surface becomes untested.
3. Replace the external database type with a Kuzushi-owned minimal structural
   interface while retaining the optional `db` field and source compatibility
   for structurally compatible consumers.
4. Remove `better-sqlite3` from production dependencies and lockfile, delete
   addon-only postinstall behavior/assertions, and retain checks for native
   Kuzushi binaries where relevant.
5. Extend packed-consumer verification to typecheck imports from both
   `kuzushi/modules` and `kuzushi/testing` without the SQLite addon installed.

## Verification

```text
pnpm install --frozen-lockfile
pnpm typecheck:all
pnpm vitest run tests/testing/public-surface.test.ts
pnpm test:coverage
pnpm verify:pack
```

## Done criteria

- Published testing helpers have behavior and coverage gates.
- Package consumers do not install/rebuild `better-sqlite3`.
- `DagContext.db` remains structurally usable and pack/type smoke tests pass.

## STOP conditions

Stop if runtime code actually loads `better-sqlite3`, removal requires breaking
the public field, or frozen install exposes unrelated lockfile corruption.
