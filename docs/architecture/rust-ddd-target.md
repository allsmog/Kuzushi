# Rust DDD Target

This document is the migration contract for the Rust-first bounded-context
layout. The goal is clearer ownership for Kuzushi's security behavior without
adding enterprise ceremony or changing operator-visible behavior.

## Ownership Rules

- `modules/` owns runtime/catalog concerns: public tool contracts, descriptors,
  option metadata, DAG descriptors, registry lookup, and dispatch adapters.
- `modules/` must not become the home for specialist security algorithms.
- Specialist security behavior belongs in `capabilities/*`.
- Static evidence, ranking, context assembly, registry matching, and narrative
  reporting belong in `evidence/*`.
- Proof state, validation, suppressions, and whitebox policy belong in
  `proof/*`.
- Repository intelligence belongs in `workspace/*`.
- Finding lifecycle, persistence, aliases, exports, and finding report
  projections belong in `findings/*`.
- Scan execution, verification, remediation, runtime governance, CLI delivery,
  TUI delivery, and provider adapters each keep their own bounded contexts.

Side effects stay at the edge. Domain modules should prefer value types,
parsers, classifiers, and decisions that can be tested without filesystem,
process, network, terminal, or model calls.

## Target Contexts

- `capabilities/`: systems hunt, Carlini threat hunt, variant/ndiff,
  threat model, x-ray, recon, agentic SAST, taint iris, deep auditor,
  classifier gate, prompt armor, vendor assessment, Chrome RCE, and plugin
  assessment behavior.
- `evidence/`: static evidence graph and store, static context, static
  registry, static ranking, static narrative, and scanner-result evidence
  indexing.
- `proof/`: proof-state vocabulary, static proof validation, whitebox policy,
  suppressions, verification classification, and proof persistence adapters.
- `workspace/`: workspace target, repository inventory, attack surface,
  artifact knowledge, source spans, and diff scopes.
- `findings/`: finding identity, deduplication, persistence, reporting,
  aliases, PR-comment projections, and workspace finding exports.
- `scan/`: scan runs, scan tasks, scan engines, subprocess execution,
  cancellation, artifacts, and scan adapters.
- `verification/`: finding validation, exploit verification, trigger
  construction, sandbox adapters, and runtime-process validation.
- `remediation/`: patch/remediation prompt construction, patch execution, patch
  validation, and tool JSON conversion.
- `runtime/`: runtime/model governance, no-silent-fallback policy, routed
  runtime dispatch, and agent tool-loop application services.
- `cli/`, `tui/`, and `openai/`: delivery and infrastructure adapters.

## Compatibility Shims

Existing public root modules stay available while behavior moves. A moved
module keeps an old root shim like:

```rust
pub use crate::evidence::narrative::*;
```

Shims are retained for public or widely used paths until a deliberate semver
migration removes them. Private-only shims can be deleted once imports and
tests prove they are unused.

## Migration Phases

1. Add roots and compatibility shims for `capabilities`, `evidence`, `proof`,
   and `remediation`.
2. Move static/evidence/proof/whitebox contexts under `evidence` and `proof`.
3. Move repository intelligence under `workspace`.
4. Move specialist security families under `capabilities`, one family at a
   time, with thin `modules/adapters/*` tool adapters preserving tool IDs.
5. Finish scan, verification, and remediation boundaries.
6. Finish CLI/TUI delivery cleanup.
7. Audit public exports, persisted formats, tool catalogs, parity, tests, and
   CRAP results.

## Test Strategy

Every phase must run:

```bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
```

Add focused tests for the behavior moved in that phase. Required coverage
includes public module exports, tool catalog stability, hidden DAG behavior,
scan/shell/run parity for touched tools, finding DB compatibility, `.kuzushi`
path compatibility, no-silent-model-fallback regressions, CLI public behavior,
TUI command/rendering behavior, and provider adapter behavior where relevant.

## CRAP Gate

Every phase must run the repo CRAP gate or an equivalent baseline comparison.
The gate must:

- keep changed/new production functions below CRAP 15;
- prevent touched existing CRAP offenders from increasing;
- report exact blockers if the tooling cannot run;
- never be claimed as passing without measurement.

The current workflow uses `cargo crap` with a saved baseline for regression
checks, plus targeted inspection of new helper files when the repo contains
pre-existing over-threshold functions.

## Non-Goals

- Do not rename public tool IDs.
- Do not change persisted schemas without migration tests.
- Do not duplicate proof-state behavior in findings, reports, CLI, or TUI.
- Do not move all specialist security logic into `modules/`.
- Do not introduce vague `utils.rs` dumping grounds or generic service layers
  around one-function behavior.
- Do not resurrect TypeScript/Ink TUI paths.
