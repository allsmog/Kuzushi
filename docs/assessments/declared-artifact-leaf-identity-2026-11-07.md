# Unanchored artifact-leaf matching claimed artifacts a run never wrote (2026-11-07)

## The defect

Three places in `kuzushi-core` answer the same question — "does this declared
artifact path name the canonical artifact `<leaf>`?" — and they answered it
three ways.

`report/application.rs` had the correct reading: take the path's final
component (`Path::file_name()`) and compare it to the leaf. The other two used
an unanchored `str::ends_with`:

```rust
// report/artifact_summary/artifact_manifest.rs
nonempty_value_string(artifact, "path").is_some_and(|path| path.ends_with(leaf))

// run_artifacts/run_failures.rs
if !available.path.ends_with(artifact) {
```

A string suffix is not a path leaf. This needs no hostile input: Kuzushi writes
two colliding pairs itself, both contracted in `artifact_contract.rs`.

- `scan-input.json` (`SCAN_PIPELINE_ARTIFACTS`) ends with `input.json`
  (`TOOL_INPUT_ARTIFACTS`).
- `phase-stages.jsonl` (`SCAN_PIPELINE_ARTIFACTS`) ends with `stages.jsonl`
  (`OPTIONAL_RUN_ARTIFACTS`).

So:

1. `artifact_manifest_summary` is the one line the Report surface prints for a
   run's `artifacts.json`. A scan run that declares its own `scan-input.json`
   was summarized as carrying the `input.json` tool input, and one that declares
   `phase-stages.jsonl` as carrying the optional `stages.jsonl` tool stage
   receipts. The report asserted artifacts that are not in the manifest it is
   summarizing, in the artifact inventory an operator reads to decide what a run
   produced.
2. `declared_failure_artifact_exists` decides which canonical artifacts the
   failure handoff reports as missing. Any declared path whose name merely ends
   with a canonical leaf — a producer-declared `phase-report.md` against
   canonical `report.md`, a `prior-run.json` against `run.json` — satisfied the
   existence check as long as a file was present at the declared path. The
   genuinely missing canonical artifact was then dropped from
   `missing_artifacts` and from the `Missing artifacts:` line of the fallback
   prompt, so a failed run looked more complete than it was to the operator and
   to the recovery prompt built from that context.

## Why this ranked first

It is a shipped evidence-honesty defect reachable from Kuzushi's own artifact
names, not from an edge case someone has to construct, and both surfaces are
ones an operator reads to decide what a run actually produced. The correct
reading already existed in the same crate, so the fix is to share the policy
rather than invent one, and the change stays inside one crate with no artifact
format, CLI, or module-contract change.

The alternative candidates were either larger than one reviewable change or
entangled with ingest policy — see the ranked list in the pull request.

## The fix

`artifact_contract.rs` already owns the spec tables and the by-leaf lookups, so
it gains the two functions that read a declared path:

- `declared_artifact_leaf(path)` — the path's final component, returning the
  path unchanged when it has none (`.`, `..`, the empty string), so a caller
  never silently reads it as another artifact.
- `declared_path_names_artifact(path, leaf)` — leaf equality.

All three call sites now ask it, and `report/application.rs::artifact_leaf`
delegates rather than keeping its own copy.

A declared artifact path is one Kuzushi built from a run directory, so reading
the platform's separators is correct here. That is the opposite of
`findings::domain::reported_source_path`, which keeps `\` as a filename byte
because a *reported* source path is literal detector data. The doc comment on
the new function records the distinction so the two are not merged later.

## What this does not claim

- It does not change any artifact format, path, schema, or label, and no
  `.kuzushi` file is read or written differently.
- It does not change which artifacts a run writes, only which ones these two
  surfaces report as present or missing.
- `findings/application/batch_occurrence/pending_receipt.rs` uses
  `Path::ends_with`, which is already component-anchored, and
  `capabilities/carlini_threat_hunt/adapters/output.rs` and
  `kuzushi-eval/src/path_cwe.rs` anchor their suffix at `/`. None of the three
  was touched.
- The forged-line-1 defect in the agentic finding normalizers (ranked second in
  the pull request) is untouched. It needs the captured-source ingest policy in
  `findings/persistence/open/finding_writes/source_binding.rs::require_anchor`
  decided first, which is more than one reviewable change.

## Verification

- All three new tests fail against the prior `ends_with` semantics and pass
  after: `cargo test -p kuzushi-core --lib -- merely_ends_like`.
- `cargo test -p kuzushi-core --lib -- report:: run_artifacts:: artifact_contract::`
  — 511 passed, 0 failed.
- `pnpm verify:quick:summary` green across all ten steps.
