# Dead-code audit (mechanical)

**Date:** 2026-07-03 · **Scope:** the whole Cargo workspace (21 crates) plus the
retained TypeScript surface under `src/`.
**Toolchain:** `rustc 1.88.0`, `cargo-machete 0.9.2`, `ts-prune`, `knip`.
**Nature:** mechanical / tool-driven. At audit time, nothing was deleted or
modified. Every finding below is a *candidate* — read the per-section caveats
before acting, because several categories are intentional API surface, not rot.

**Remediation status (2026-07-03):** the production Cargo dependency entries in
§1 have been removed; the `kuzushi-tui` / `kuzushi-cli` compile gap in §2 is
closed and the strict unused-warning pass now completes; the high-confidence
TypeScript cleanup in §4 is applied by making `PrintOptions` module-private and
removing the duplicate runtime schema export alias. The intentionally dirty
`tests/fixtures/dep-hygiene/rust` fixture and low-confidence public/SDK export
candidates remain unchanged by design.

## TL;DR

| # | Tool | What it found | Confidence | Est. removable LOC |
|---|------|---------------|-----------|--------------------|
| 1 | `cargo-machete` | 19 unused `[dependencies]` entries across 15 crates | High | ~19 manifest lines (+ build-time) |
| 2 | `knip` (TS exports) | 79 exports with no in-repo importer | Low — retained SDK surface | ~150 (do not cut blindly) |
| 3 | `ts-prune` (TS exports) | 188 "unused" incl. barrel re-exports | Low — noisier superset of #2 | (subset of #2) |
| 4 | `pub use` shim scan | 730 `pub use` / 2 751 total re-exports analysed | — | **0 confirmed removable** |
| 5 | `RUSTFLAGS="-W unused"` build | dead_code / unused_* warnings | — | **0** (see coverage gap) |

**Headline at audit time:** the only high-confidence, immediately-actionable
dead code was a set of ~19 unused Cargo dependencies. The compiler's own
`-W unused` pass reported **zero** dead code or unused imports; every `pub use`
re-export was still reachable; and the TypeScript "unused exports" were almost
entirely the deliberately-retained third-party SDK surface.

---

## 1. `cargo-machete` — unused dependencies

**Command:** `cargo machete` (workspace root). **Confidence: high.** Each hit
was hand-checked against the crate source to rule out `derive`-only or
re-export false positives (cargo-machete's usual blind spots); none were false
positives in the spot-checks. Each removable entry is one line in the crate's
`Cargo.toml`, and dropping it trims that crate's compile graph.

Ranked by crate (most entries first):

| Path — evidence — est. LOC |
|---|
| `crates/kuzushi-bdd-tui/Cargo.toml` — `async-trait`, `serde_json`, `tokio` unused — **3 lines** |
| `crates/kuzushi-sandbox/Cargo.toml` — `anyhow`, `serde_json` unused (no `anyhow`/`serde_json` reference in `src/`) — **2 lines** |
| `crates/kuzushi-mcp-threat-intel/Cargo.toml` — `serde` unused (only `serde_json` is used) — **1 line** |
| `crates/kuzushi-mcp-context/Cargo.toml` — `serde` unused — **1 line** |
| `crates/kuzushi-mcp-gtags/Cargo.toml` — `serde` unused — **1 line** |
| `crates/kuzushi-mcp-threat-model/Cargo.toml` — `serde` unused — **1 line** |
| `crates/kuzushi-mcp-codeql/Cargo.toml` — `serde` unused — **1 line** |
| `crates/kuzushi-mcp-treesitter/Cargo.toml` — `serde` unused — **1 line** |
| `crates/kuzushi-mcp-x-ray/Cargo.toml` — `serde` unused — **1 line** |
| `crates/kuzushi-mcp-entry-points/Cargo.toml` — `serde` unused — **1 line** |
| `crates/kuzushi-mcp-revng/Cargo.toml` — `dirs` unused — **1 line** |
| `crates/kuzushi-mcp-common/Cargo.toml` — `thiserror` unused (no `derive(Error)` / `thiserror` in `src/`) — **1 line** |
| `crates/kuzushi-cli/Cargo.toml` — `kuzushi-mcp-common` unused (no `mcp_common` reference in `src/`) — **1 line** |
| `crates/kuzushi-tui/Cargo.toml` — `uuid` unused (only appears in test *string literals*, not the crate) — **1 line** |
| `crates/kuzushi-codeindex/Cargo.toml` — `async-trait` unused — **1 line** |

**Total: 15 crates, ~19 dependency lines.** The recurring `serde` hits across
the seven MCP crates are the same pattern — those crates use `serde_json` (a
separate crate) but never `serde`'s derive/traits directly.

**Excluded (not production code):**
`tests/fixtures/dep-hygiene/rust/Cargo.toml` (`anyhow`, `serde`, `tokio`) — this
is an intentionally-dirty *test fixture* for the dep-hygiene scanner; leave it
alone. cargo-machete also logged one benign IO error resolving that fixture's
`src`.

**Note on accuracy:** cargo-machete parses `use` statements, so a dep consumed
only through a proc-macro `derive` can false-positive. The spot-checks above
(`grep` for the crate/trait in each `src/`) found genuine non-use in every case
sampled, so treat the list as reliable — but re-run `cargo build -p <crate>`
after each removal, since that is the real oracle.

---

## 2. `RUSTFLAGS="-W unused"` workspace build — dead_code / unused warnings

**Command:** `RUSTFLAGS="-W unused" cargo check --workspace --all-targets
--message-format=short`, re-run per-crate to work around the build gap below.

**Result: ZERO `dead_code` / `unused_*` warnings across every crate that
compiles.** Grouped by crate, the count is `0` for all of:
`kuzushi-core`, `kuzushi-openai`, `kuzushi-eval`, `kuzushi-bdd-tui`,
`kuzushi-codeindex`, `kuzushi-sandbox`, `kuzushi-mcp-common`, and all eleven
`kuzushi-mcp-*` servers.

Two things explain the clean result rather than it being suspicious:

1. **`kuzushi-core` exposes its entire module tree as `pub mod`** (via the
   `public_modules!` macro in `src/lib.rs`). rustc does not lint unused *public*
   items, so `pub use` re-exports there are never flagged — see §4 for why that
   matters. The non-public `pub(crate) use` re-exports *would* be flagged if
   truly unused, and none were.
2. **`crates/kuzushi-tui/src/lib.rs` carries a crate-wide
   `#![allow(unused_imports)]`** with a documented rationale: the crate flattens
   its module tree with `pub(crate) use mod::*` + `use super::*`, which produces
   ~190 false-positive `unused_imports` the compiler can't see through. This is a
   deliberate suppression, not rot — but it does mean unused imports *inside*
   `kuzushi-tui` are invisible to this pass.

### ⚠️ Coverage gap (disclosed)

The full-workspace `-W unused` build **fails to compile `kuzushi-tui`** in the
current working tree, so `kuzushi-tui` and its dependents (`kuzushi-cli`) were
**not** linted for unused code:

```
crates/kuzushi-tui/src/app/tool_runner/mod.rs:17:5:
  error[E0432]: unresolved import `kuzushi_core::ToolExecutionContext`
crates/kuzushi-tui/src/app/scan/start_scan/scan_startup.rs:264:19:
  error[E0422]: cannot find struct `ToolExecutionContext` in this scope
```

This is a **pre-existing breakage in the uncommitted `design-sync/kuzushi-tui-kit`
working tree** (a `ToolExecutionContext` moved/renamed in `kuzushi-core` without
the two `kuzushi-tui` references being updated), *not* a dead-code finding, and
was **not** fixed per the "do not modify source" constraint. Until it compiles,
`dead_code`/unused coverage for `kuzushi-tui` + `kuzushi-cli` is limited to the
`#![allow(unused_imports)]`-suppressed baseline. Re-run this section after that
build is repaired for complete coverage.

---

## 3. Stale compatibility shims (`pub use` re-exports)

**Method (fully mechanical):** parsed all **730 `pub use`** statements under
`crates/` (2 751 counting `pub(crate) use` / `pub(in …)`), expanded every braced
/ renamed / glob tree into individual exported names, then searched the entire
workspace for consumers importing through the **shim path**
(`<module>::<Name>`) versus the **real path** (`<module>::<submodule>::<Name>`).
A second verification pass then re-classified each zero-shim-path candidate by
checking whether the name is still reachable via (a) unqualified use in the
defining file, (b) `super::<Name>` / `super::*` from a sibling in the module
subtree, or (c) a `#[cfg(test)]`-gated test re-export.

**Funnel:** 730 → 60 statements with no direct shim-path consumer → after
verification, **0 confirmed-removable shims.**

### Finding: no removable stale shims exist

Every one of the 60 "no shim-path consumer" candidates falls into a category
that keeps it live:

- **37 are cleared outright** — the symbol is imported via the *real path* or
  pulled in via `use super::*` namespace-flattening by a sibling module (the
  dominant idiom in `kuzushi-core/src/offense`, `code_nav`, `module_recommender`,
  `kuzushi-tui/src/ui_view_models`, `kuzushi-codeindex`, `kuzushi-mcp-common`).
  Example: `crates/kuzushi-core/src/capabilities/chrome_rce/mod.rs:8` —
  `#[cfg(test)] pub(crate) use domain::hot_path_finding;` is a deliberate
  **test-only** affordance consumed by `chrome_rce/tests.rs`; production code
  reaches the symbol through the real `domain::hot_path_finding` path.
- **21 were false-positives of the shim-path heuristic** — flagged as "no shim
  consumer," but the symbol is still used through the real submodule path
  (`super::argv::build_argv`, `crate::…::domain::hot_path_finding`,
  `super::response::strip_provider_prefix`, …) and/or by tests via `super::*`.
  These `pub(crate) use`/`pub use` lines are ordinary `mod.rs` API flattening,
  **not** DDD-migration shims.

**The compiler agrees:** the `-W unused` build (§2) emitted **no**
`unused_imports` for any non-public re-export, which is the authoritative signal
that no `pub(crate) use` re-export is truly dead.

### Zero shims are annotated as migration shims

A targeted grep for shim intent —
`pub use` lines near `compat` / `shim` / `deprecated` / `legacy` / `migration`
comments — returned **nothing**. The CLAUDE.md guardrail ("DDD-migration shims
must be removed once downstream imports are updated") therefore has **no
detectable violations**: there are no leftover, annotated compatibility shims
with zero consumers in the tree.

### Soft candidates (public-API re-exports, in-workspace consumers = 0)

Two facade re-exports export names that no workspace crate imports through
*any* path. Because they are `pub use` inside a `pub mod`, rustc cannot flag
them, and they may be intentional public API for downstream workspace crates
(some of which — `kuzushi-tui`/`kuzushi-cli` — don't currently compile, see §2,
so this cannot be mechanically confirmed). Listed as low-confidence only:

| Path — evidence — est. LOC |
|---|
| `crates/kuzushi-core/src/capabilities/mod.rs:33` — `pub use threat_intel::{ apply_threat_intel_catalog, list_threat_intel_catalog, load_catalog_from_path, CatalogEntry, CatalogFile, CatalogSeverity, SUPPORTED_SCHEMA_VERSIONS }` — no in-workspace consumer via `capabilities::…`; verify against `kuzushi-cli`/`kuzushi-tui` once they build — **~5 lines** |
| `crates/kuzushi-mcp-common/src/lib.rs:14` — `pub use schema::{ EdgeKind, FileSpan, Method, Path as PathResult, Symbol, SymbolKind }` — these six names have no in-workspace importer through the crate root (`Position`, `Range` do) — **partial line edit** |

**Do not remove these mechanically.** They are the published surface of the
respective crates; confirm no external/SDK consumer first.

---

## 4. TypeScript surface — `knip` and `ts-prune`

The TypeScript under `src/` is, per `CLAUDE.md`, a **retained SDK / testing /
export compatibility surface for third-party module authors** — it is *not* the
runtime (the CLI is Rust). This dominates every finding below: an export with no
importer *inside this repo* is the normal, intended state for a published SDK
type. Treat this whole section as **low confidence** and cut nothing without
confirming no external module author depends on it.

### `knip` (authoritative — understands the `exports` map)

**Command:** `pnpm dlx knip`. **Result: 79 unused exports, 1 duplicate export,
and no unused *files*** (knip reported no "Unused files" section — every `.ts`
file is still referenced).

Ranked by file (most exports first):

| Path — evidence — est. LOC |
|---|
| `src/schemas.ts` — 35 unused exports, almost all one-line `export type XZ = z.infer<typeof XSchema>` aliases (`VerdictZ`, `FindingZ`, `ExploitChainZ`, `RawTriageOutput`, `ValidationError`, …) — **~38 LOC** |
| `src/modules/types.ts` — 24 unused exports: 15 re-export lines (`HostCapability`, `WorkspaceHandle`, `ToolLogger`, …) + interfaces `Finding` (~8), `AgentActivityMeta` (~10), `KnowledgeModule`, `ToolPolicy`, `ReadyPeerInfo`, `ModuleReadyContext` — **~55 LOC** |
| `src/contracts.ts` — 13 unused type aliases (`ProofVerdict`, `PatchStatus`, `ReportMode`, `DynamicCoverageMode`, …), 1 line each — **~13 LOC** |
| `src/modules/vendor-assessment/types.ts` — 3 unused: `VendorAssessmentKindSpec` (~5), `VendorAssessmentCompletenessGate` (~7), `VendorAssessmentDocumentStatus` (1) — **~13 LOC** |
| `src/copilot/print.ts:23` — `PrintOptions` interface — most likely *genuinely* dead (the `copilot/shell.ts` runtime was deleted in the Rust migration) — **~12 LOC** |
| `src/modules/host-handles.ts:43` — `ModuleRunStepLike` interface — **~8 LOC** |
| `src/modules/registry.ts:28` — `ModuleRegistryEvents` interface — **~5 LOC** |
| `src/modules/schema.ts:83` — `ZodModuleManifest` type — **~1 LOC** |

**Duplicate export (1):** `src/schemas.ts` re-exports
`AgentRuntimeCredentialsSchema` / `AgentRuntimeConfigSchema` twice — a harmless
one-line-each cleanup.

**Highest-confidence TS cut:** `src/copilot/print.ts` `PrintOptions` — `copilot/`
is the one non-SDK directory here and its interactive runtime was removed during
the Rust migration, so this is the least likely to have an external consumer.
Everything under `src/modules`, `src/schemas`, `src/contracts`, `src/index`,
`src/testing` is the SDK contract — leave unless you are intentionally trimming
the published API (which needs a `RELEASING.md` migration note per CLAUDE.md).

### `ts-prune` (noisier superset — for cross-reference only)

**Command:** `pnpm dlx ts-prune -p tsconfig.json`. Reported **319 lines** — 188
"unused" plus 131 flagged `(used in module)`. This is a strict superset of the
knip result and is **less trustworthy here**: ts-prune does not resolve the
package `exports` map, so it reports every barrel re-export
(`src/index.ts` 19 lines, `src/modules/index.ts` 70 lines, `src/testing/index.ts`
42 lines) as "unused" even though those barrels *are* the public entry points.
Distribution of the 188 by file: `src/modules/index.ts` (70),
`src/testing/index.ts` (42), `src/schemas.ts`/`src/contracts.ts` (overlap with
knip), `src/agent-runtime/types.ts` (20). **Prefer knip's 79 over this list**;
the extra ~109 ts-prune entries are barrel indirection, not dead code.

---

## Method notes & reproduction

```bash
# 1. unused deps
cargo install cargo-machete --locked && cargo machete

# 2. dead_code / unused (per-crate to route around the kuzushi-tui build break)
RUSTFLAGS="-W unused" cargo check --workspace --all-targets --message-format=short

# 3. shim scan — expand every pub-use tree, search workspace for shim-path vs
#    real-path consumers, then verify reachability via super::*/#[cfg(test)].
#    (scripts kept in the audit scratchpad; pure grep + AST-free text analysis.)

# 4. TypeScript
pnpm dlx knip                       # authoritative: honours the exports map
pnpm dlx ts-prune -p tsconfig.json  # cross-reference only (barrel-noisy)
```

**Confidence ladder for acting on this report:**
1. **Act now:** §1 unused Cargo deps (verify each with `cargo build -p <crate>`).
2. **Act with care:** §4 `src/copilot/print.ts` and the duplicate export.
3. **Investigate, don't auto-cut:** §3 soft candidates and the rest of §4 — all
   are public/SDK surface that a mechanical pass cannot prove dead.
4. **Blocked:** re-run §2/§3 for `kuzushi-tui` + `kuzushi-cli` once the
   `ToolExecutionContext` build break is resolved.
