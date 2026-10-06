# Report boundary audit (2026-10-06)

Scope: `report:build`, `report:sarif` and `workspace:export-findings`, checked
against the bounded-investigation contract: exports must keep human decisions,
observation, source and context provenance, coverage limits and consumption.
Each defect below was first shown failing through a real test before it was
changed. Fixtures are labeled source that is never executed; no provider
request was made.

## Defects proven and fixed

1. **A failed receipt write replaced the export.** `workspace:export-findings`
   wrote the export with a plain `fs::write` and then the investigation
   receipt. When the receipt write failed, the new export sat beside a missing
   or stale receipt (`receipt_write_failure_leaves_the_previous_export_intact`
   failed before the change). Single-file exports now write the receipt first,
   and both files are replaced atomically through `fs_atomic::write_atomic`.
   The Markdown bundle owns its directory, so its receipt still follows the
   bundle. `report:sarif` also writes atomically now.
2. **`report:build` reported an export as its source run.** The implicit
   "latest run" skipped only running runs and earlier `report:build` runs, so a
   later `report:sarif` or `workspace:export-findings` run became the reported
   analysis (`latest_report_source_skips_later_export_and_read_only_runs`
   failed with `d-sarif`). The implicit source now skips tools that the shared
   descriptor classification marks as Report or Read. The `report:build`
   executor supplies that predicate, so the report reader itself never
   consults module policy (the DDD boundary rule). An explicit `runId` still
   selects any run.
3. **`report:sarif` could not report a study.** It always exported every
   confirmed finding in the workspace and rejected `campaignId` as unknown.
   It now declares `campaignId` (alias `campaign_id`), selects only that
   study's observations through the shared investigation report service, and
   embeds the same receipt `workspace:export-findings` uses in
   `runs[0].properties.kuzushiExport.investigation`. Output without
   `campaignId` is unchanged.
4. **Human decisions did not say which source they judged.** Decisions are
   ledger-wide; nothing in an export showed whether a confirmation was made
   before the code changed. Each decision already records the event watermark
   it was made at, and each observation records its run, source snapshot and
   event sequence. Export records now carry `reviewDecisionBasis`: the run and
   source snapshot the latest decision was made against, any later observation,
   and whether that later observation's source differs. No event field or
   projection schema changed, and no decision is rewritten. JSON, JSONL, SARIF
   result properties and the Markdown bundle carry it; CSV keeps its public
   columns.

## Related fixes

- **Earlier-source Scan attempts used the untyped projection.** Typed receipt
  hydration covered only the current attempt, so the Scan page fell back to
  run-summary totals for an earlier-source selection. One shared
  `displayed_phase_attempt` now drives both the Scan projection and its
  receipt hydration.
- **Captures lost Enter to the capability picker.** With the startup picker
  visible, Ctrl+R history search and a pending plan question could not accept
  with Enter. The picker now yields while either capture is active.
- **The expanded capability picker could not page and mislabeled `e`.** It now
  pages with PgUp/PgDn by its visible row budget, advertises that, and labels
  `e` by the state it switches to (`expert engines` or `phase only`).
- **Panic sites in pane-facing code.** Scope review and context generation
  view models and the scope form renderer no longer `unwrap()` optional state;
  they degrade to an empty projection instead of risking a raw-mode panic.

## Stale tests repaired

These failed deterministically in the committed tree; the behavior they
protect was kept and the assertion updated to the current contract:
threat-model artifact label (`immutable threat model`, including the negative
check), SAST cancellation wording (`canceled` and `cancelled` both accepted;
persisted statuses still asserted), `pack:scopes` display name and
`pack:suggest-scopes` parity documentation, study usage wording, Campaign view
selection, command-history tests moved off the startup picker, and an
entry-point paging test given a viewport where its detail overflows.

- **`--since` could not scan changed files.** File scopes refused every
  native engine, including secret scanning and Semgrep, which read exact
  files. File scopes now scan exactly those files with engines that support
  it; directory-only engines still refuse and are named, never widened to a
  parent directory.
- **A worker-bound test raced under load.** It now waits until both hydration
  workers are inside the reader, so the cap rather than an early cancellation
  decides the third request.

## Verification

Full suites after the final change, run one target at a time because the disk
was nearly full: `kuzushi-core` library 5560 passed (6 ignored), `kuzushi-tui`
library 3739 passed, all other crates 987 passed with 51 of 51 BDD scenarios,
and the core and TUI integration targets passed after five text snapshots
were regenerated for current tool counts and the `/scopes` command. Logs are in
`.git/bounded-investigations/` (`core-lib-final2.log`, `tui-lib-final2.log`,
`other-crates-final3.log`, `core-tui-integration-final.log`).

J95 at `/tmp/kuzushi-bounded-investigations-tui/20261006-101326/J95/` (native
SHA-256 `55c75fc9cbac8ed82b785d4bc699b0ecef218015722ecda8db3ce437745db406`)
records 55 machine passes and nine passing screen judgments, including the
typed earlier-source Scan page.

## Limits

The decision basis follows the store's stable identity key, the same key used
when the decision is written. It describes the latest decision only; earlier
decisions stay in the ledger. Raw artifact bundling, complete engine omission
lists and actual provider prompts are still not part of the receipt and remain
listed in its limitations. No delivery milestone is closed by this audit.
