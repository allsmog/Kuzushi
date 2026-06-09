# Codebase Simplification Hotspots

Audit date: 2026-05-06.

This assessment feeds `scripts/ralph-uncle-bob-simplify.sh`. It is a
refactor-only planning document: use it to choose small simplification slices,
not to justify behavior changes.

## Current Hotspots

Largest current Rust and TypeScript production files:

| Lines | Path |
| ---: | --- |
| 14,484 | `crates/kuzushi-core/src/modules.rs` |
| 10,198 | `crates/kuzushi-tui/src/app.rs` |
| 4,798 | `crates/kuzushi-tui/src/renderer.rs` |
| 4,196 | `src/bus/orchestrator.ts` |
| 3,059 | `crates/kuzushi-core/src/scan.rs` |
| 2,861 | `crates/kuzushi-core/src/verify.rs` |
| 2,339 | `crates/kuzushi-core/src/findings.rs` |
| 2,283 | `crates/kuzushi-core/src/systems_hunt.rs` |
| 2,274 | `crates/kuzushi-core/src/variant_ndiff.rs` |
| 2,119 | `src/store.ts` |

The active cleanup priority is Rust-first because the migration made Rust the
primary operator path and because the largest files are now Rust modules.

## Existing Quality Reports

The `docs/notes/CODE_QUALITY_*.md` reports remain useful, but several findings are
partially stale after the Rust TUI migration. Treat them as background:

- `CODE_QUALITY_DRY.md`: good patterns for avoiding cosmetic DRY work.
- `CODE_QUALITY_UNUSED.md`: warns that exported TypeScript SDK surfaces need a
  manual public-contract audit before deletion.
- `CODE_QUALITY_LEGACY.md`: separates removable shims from load-bearing
  persisted-format compatibility.
- `CODE_QUALITY_COMMENTS.md`: supports deleting decorative/in-motion comments
  while keeping comments that explain external API or runtime invariants.
- `CODE_QUALITY_TYPES*.md`: shows that most weak-type work is boundary-shaped;
  do not collapse public contracts casually.
- `CODE_QUALITY_CYCLES.md`: no TypeScript circular dependency remediation is
  currently needed.

## Refactor Rules

- Preserve behavior, CLI output contracts, persisted `.kuzushi` formats, and
  scan/shell/run mode parity.
- Do not weaken model/runtime enforcement or introduce silent fallback paths.
- Do not resurrect TypeScript/Ink UI code.
- Prefer extraction by concept over mechanical file splitting.
- Keep commits small enough to review: one story, one coherent slice, one
  passing gate.
- Add tests only when a behavior boundary moves or a new helper captures logic
  that was previously implicit.

## Preferred Order

1. Decompose `crates/kuzushi-core/src/modules.rs` by module family.
2. Extract Rust TUI app state transitions and command reducers from
   `crates/kuzushi-tui/src/app.rs`.
3. Split Rust TUI rendering into plain output, view-line builders, and shared
   widgets/helpers.
4. Extract verification phases from `crates/kuzushi-core/src/verify.rs`.
5. Split finding persistence/query/reporting helpers out of
   `crates/kuzushi-core/src/findings.rs`.
6. Simplify `scan.rs`, `systems_hunt.rs`, and `variant_ndiff.rs` only after the
   top three hotspots are no longer dominating review cost.
