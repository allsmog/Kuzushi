# Store stress + fold performance baseline

First recorded 2026-07-19 on a 16-core GCP devpod (shared, moderately
loaded). Regenerate with the two ignored harness tests and update this
table when fold code changes:

```sh
cargo test -p kuzushi-core --lib --release -- --ignored perf_baseline --nocapture
cargo test -p kuzushi-tui  --lib           -- --ignored perf_baseline --nocapture
```

The synthetic data lives only inside the ignored tests (tempdir stores,
deleted on drop; in-memory vectors) — no shipping code path generates it.

## Pure folds — 10,000 findings / 30,000 review-decision records

Core folds measured in **release**; every finding carries a three-round
decision history so the latest-decision-wins reversal is exercised on all
rows.

| Fold | Time | Notes |
| --- | --- | --- |
| `trend_metrics` | 3.0 ms | 10k decided |
| `latest_confirmed_finding_ids` | 2.5 ms | 3,333 confirmed |
| `history_strip_label` (90-snapshot window) | 16 µs | sparkline render |

Shell folds measured in **debug** (so real-world release numbers are
strictly better); 10k in-memory findings, 30k decision records:

| Fold | Time | Notes |
| --- | --- | --- |
| backlog projection (cold cache) | 47 ms | 3,334 visible after untriaged filter |
| backlog projection (warm cache) | 33 ms | |
| `review_queue_model` (backlog) | 74 ms | clamped to 200 rows |
| `refresh_campaign_deck` (trend + history IO) | 14 ms | |
| `refresh_workspace_trend` | 13 ms | |

**Verdict: every fold is 7–150× under the 500 ms budget at target scale.
No index or batching work needed.** The folds are BTreeMap/linear passes
over already-loaded rows; cost is dominated by the store reads below.

## Store-backed reads — measured at 1,000 findings / 3,000 decisions (release)

| Operation | Time @1k | Linear extrapolation @10k |
| --- | --- | --- |
| `list_all_findings` | 42 ms | ~420 ms |
| `list_review_decisions_for_findings` | 11 ms | ~110 ms |
| `campaign:status` (store load + fold + history) | 55 ms | ~550 ms |
| `campaign:coverage` | 54 ms | ~540 ms |

Reads scale linearly with row count (sqlite full-projection loads).
At 10k findings `campaign:status` lands right at the ~500 ms line —
acceptable for a status poll; if a future ledger passes ~20k findings,
the first lever is paginating `list_all_findings` for the trend fold
(the fold itself needs only finding ids + decisions).

## 2026-07-20 rerun — expression indexes for per-insert point lookups

`finding_observations` gained expression indexes on
`json_extract(finding_json, '$.id')`, `'$.fingerprint'`, and a partial
`run_id` index (`storage_v3/projection_schema.rs`, applied automatically
on open). Before, every insert's `v3_finding_by_projected_id` /
`v3_finding_by_fingerprint` lookup full-scanned observation history
through `json_extract` (~40 ms/row once history reached a few thousand
rows — quadratic over an import). The lookups are now index searches;
`projected_id_and_fingerprint_lookups_use_expression_indexes` pins the
query plan so a regression reintroduces a test failure, not a slow scan.
The triage projection UPDATE and `finding_ids_for_fingerprint` share the
same expression shapes and the same indexes.

Rerun of the release harness (same box class, 1k findings + 3k decisions):

| Operation | 2026-07-19 | 2026-07-20 |
| --- | --- | --- |
| store generation (1k+3k, fsync-bound) | 138 s | 141 s |
| `list_all_findings` | 42 ms | 44 ms |
| `list_review_decisions_for_findings` | 11 ms | 11 ms |
| `campaign:status` | 55 ms | 58 ms |
| `campaign:coverage` | 54 ms | 56 ms |

At 1k rows the harness is fsync-dominated, so aggregate timings are
unchanged (within shared-box noise); the index removes the term that
*grew* with history size, which the 1k-row harness barely exercised. The
next slow term for bulk import remains the per-record fsync documented
below.

## Known limit: write throughput (why the harness is 1k, not 10k, on-store)

The event-sourced writer (append + hash chain + projection per record)
sustains **~29 writes/second**: 1k findings + 3k decisions took 138 s;
the originally planned 10k/30k store generation would run ~45 minutes.
This does not affect interactive use (single decisions, scan batches),
but it bounds bulk paths — `workspace:import-findings` on a
multi-thousand-row external ledger will be slow. If bulk import becomes
a real workflow, batch events per transaction/fsync instead of per
record; do not weaken per-decision durability for the interactive path.

## 2026-09-06 — trend fold reads decision subjects, not findings

`campaign:status` used to load every finding through `list_all_findings`
(full `finding_json` deserialization, source merge, verification and
suppression hydration) only to hand `list_review_decisions_for_findings` the
`(finding_id, identity_id)` pair per row. `FindingStore::list_all_review_decisions`
now projects exactly those two columns from the shared latest-observation
ranking CTE (`v3_finding_reads.rs`, `LATEST_REVIEW_DECISION_SUBJECTS_SQL`) and
feeds them to the same decision query, so the status trend no longer scales
with finding payload size. `review_decisions.rs` tests pin that the narrow
read returns byte-identical records to the full walk. The ignored harness
prints `PERF list_all_review_decisions` beside `PERF list_all_findings` for a
direct comparison; rerun it with the command at the top of this page when
either read changes.
