# Hardening audit — July 2026 (items 2–9, L1–L3, P1–P4)

Working log for the operator-ordered audit+patch sweep. One section per item;
each section records what was audited, holes found, fixes + regression tests,
and accepted residual risk. All changes left uncommitted per standing policy.

## Item 2 — Path containment on operator/external inputs

Audited: `normalize_path_option` family in
`crates/kuzushi-core/src/modules/builtins/with_v2_builtins/execution.rs`
(workspace-read / state-write / target-write / external-read / external-write /
executable), `WorkspaceTarget::new` (root is canonicalized at construction),
the symlink-hardened walkers in `workspace/domain/workspace_state_io.rs`, and
every write sink for operator output paths.

### Holes found and fixed

1. **State-write symlink escape (core).** `normalize_state_write_path` checked
   `.kuzushi/` containment on the *pre-canonicalization* lexical path, then
   only re-checked workspace containment after canonicalization. A symlink
   under `.kuzushi/` pointing elsewhere **inside** the workspace passed both
   checks, letting a state-write reach target source files without target-write
   authorization. Fixed: `ensure_state_write_containment` re-checks the
   canonical path against the canonical state root.
   Test: `state_write_symlink_cannot_escape_state_root_into_workspace`.

2. **CLI `kuzushi export` output uncontained.** `resolve_export_output` joined
   relative paths and passed absolute paths through with no `..` rejection, no
   symlink checks, no containment. Fixed via the new shared helper.
   Test: `application::export::tests::export_output_outside_workspace_is_rejected`.

3. **TUI export service uncontained.** `services/workspace.rs::workspace_output_path`
   had the same raw-join pattern. Fixed via the shared helper.
   Test: `workspace_export_findings_to_temp_path` (rewritten to assert
   rejection of outside paths + success inside the root).

4. **`kuzushi ci --summary` uncontained.** `summary_path` joined/passed through
   raw operator paths. Fixed via the shared helper (default state-dir path
   unchanged). Test: `summary_path_outside_workspace_is_rejected`.

5. **Executor-level defense for `workspace:export-findings`.** The executor
   re-resolved raw input with a plain join; safe behind the registry prepare
   boundary (`output` is `.target_write()`), but direct executor invocation
   bypassed containment. Now uses the shared helper.
   Test: `export_workspace_findings_tool_rejects_output_outside_workspace`.

### Shared helper

`workspace::resolve_contained_output_path(root, output)` in
`workspace/domain/workspace_state_io.rs`: canonicalizes the root, maps
absolute paths to root-relative (rejecting anything outside), then reuses
`validated_workspace_descendant` — Normal-components-only (`..` rejected),
symlink rejected at every component, no directory creation (a failed
operation leaves no partial artifacts). Unit tests cover traversal, outside
absolutes, symlinked-subdir escape, and the no-create guarantee.

### Verified-safe as designed

- `sinksPath` / `modelsDir` / `importPath` (cpg:build, codeql:create-db) are
  `.external_read()`: canonicalize-only reads of out-of-band artifacts, by
  design; the write side copies into fixed canonical `.kuzushi` destinations,
  and import sources are validated (file magic / codeql-database.yml).
- `normalize_external_write_path` writes anywhere only behind
  `enforce_path_write_authorization` (explicit operator authorization with
  operation binding).
- Prefix checks use component-wise `Path::starts_with` (no `/a/bc` vs `/a/b`
  confusion); workspace root is canonical from `WorkspaceTarget::new`.

### Residual (accepted)

- TOCTOU between prepare-time canonicalization and execute-time IO: a symlink
  swapped in after validation is not re-checked at open time (no
  openat2/O_NOFOLLOW plumbing). Local-attacker race on an operator box;
  mitigated for state IO by the symlink-rejecting walkers which are used at
  write time for state files.
- `prompt-armor:report` executor still raw-joins its `output` when invoked
  without the registry boundary; production dispatch always prepares (option
  is `.target_write()`), so left as-is to avoid a second containment policy
  against a target-scoped root.

## Item 3 — Process lifecycle: kill targeting, pid reuse, zombies

Audited: `campaign_run/child.rs` (job child spawn/bound/reap), the dispatcher
shutdown path in `campaign_run/mod.rs`, the TUI campaign deck launch/kill in
`app/campaign.rs`, and every kill call site for persisted-pid usage.

### Holes found and fixed

1. **Deck-launched dispatcher zombie leak (the observed defunct processes).**
   `spawn_detached_dispatcher` returned only `child.id()` and dropped the
   `std::process::Child` — std children are never reaped on drop, so every
   dispatcher that exited stayed `<defunct>` for the life of the TUI. Fixed:
   the handle is kept in `RuntimeState::dispatcher_child`; deck refresh calls
   `reap_exited_dispatcher()` (try_wait) and clears the pid chip; kill reaps
   after signalling. Tests: `deck_refresh_reaps_an_exited_dispatcher_and_clears_its_pid`,
   `kill_and_reap_collects_a_live_dispatcher_without_leaving_a_zombie`.

2. **Deck kill pid-reuse race.** `campaign_kill` ran `/bin/kill -9 -<pid>` on
   a bare stored pid. Once reaping exists, that pid can be recycled — the
   deck could SIGKILL an innocent process group. Fixed: kill requires the
   held child handle; `try_wait == None` proves the pid still belongs to our
   un-reaped dispatcher (kernel cannot recycle an un-reaped pid), and an
   already-exited dispatcher is reported instead of signalled
   (`kill_and_reap_reports_an_already_exited_dispatcher`). If the handle is
   missing the deck refuses to kill blind.

3. **Job children orphaned by dispatcher SIGKILL.** Job children ran in their
   own process groups with `kill_on_drop`, which does nothing when the
   dispatcher is SIGKILLed — children (and their scanner grandchildren)
   survived unowned. Fixed: `PreparedProcessGroup` (the scan layer's
   lifeline-pipe guard, now `pub` from `kuzushi_core::scan`) owns each job's
   group; when the dispatcher dies for any reason the kernel closes the
   lifeline and the guard SIGKILLs the whole group. Core already proves the
   primitive under SIGKILL (`scanner_group_dies_when_its_owner_is_sigkilled`).

4. **Scanner stragglers after job completion.** Dropping the guard at report
   time sweeps the group, so a job that leaves background grandchildren no
   longer leaks them. Test: `job_grandchildren_die_when_the_job_completes`.

### Verified-safe as designed

- Dispatcher-side kills can't hit recycled pids: the group leader is the
  dispatcher's own un-reaped child at signal time, and every kill path
  `wait()`s afterward (no dispatcher-side zombies).
- No code kills a pid/pgid parsed from `queue.json` or `run.json`; stale
  `running` rows render muted in `jobs` precisely because their liveness
  cannot be verified — that contract is intact.

### Residual (accepted)

- One `/bin/sh` lifeline guard per job child (same cost the scan engines
  already pay per scanner).
- Long-lived defunct **test** binaries (`kuzushi_core-*`, `kuzushi_tui-*`)
  can still appear when an external watchdog SIGKILLs a cargo test *runner*
  whose harness held un-reaped children; not a production code path.

### Concurrent-edit note

While testing, `key_dispatch.rs` gained an unrelated Shift+Tab/BackTab
normalization edit from another session mid-build (one transient E0425 from
reading the file mid-write). The edit is coherent and was left untouched.

## Item 4 — Crash-consistency of the store, queue, and sentinels

SIGKILL-at-any-write-point enumeration:

| Artifact | Crash state | Recovery |
| --- | --- | --- |
| `queue.json` | Never torn: every transition republishes via tmp+rename. A stale `.json.tmp` may remain (overwritten next save). | Stale `running` rows recovered to `planned` on next dispatcher open (pre-existing). |
| `events.jsonl` (campaign) | Torn tail possible (plain append). | History-only artifact; no reader folds it into state. |
| `plan.json` | Never torn: `write_json_atomic`, and it is written **after** per-job scope/prompt materialization, so a mid-plan kill leaves no committed plan pointing at half-materialized files. | Re-run `campaign:plan`. |
| `done.json` | Staged `.done.json.tmp` + rename; requires the run dir to exist; written last. | Missing `done.json` = non-terminal; `jobs` renders disk `running` rows without a live twin as Stale. |
| `trace.jsonl` | Torn tail possible. | All folds are torn-tail tolerant (budget guard tested; settlement path skips unparsable tails). |
| v3 event-log segments | **Was a store-bricker** (fixed, below). | — |
| Ledger import | **Left partial rows under a dead run** (fixed, below). | — |

### Holes found and fixed

1. **Torn event-log tail bricked the findings store.** A writer killed
   mid-append (or a power cut) leaves a newline-less partial line — possibly
   cutting a multi-byte UTF-8 character. `read_all` hard-errored on either
   (`read_to_string` UTF-8 failure or `parse_event_line`), and since every
   open/head/verify goes through `read_all`, the entire store became
   unusable. Fixed: readers tolerate a torn, line-limit-bounded,
   newline-less tail **only on the active (last) segment** (`split_torn_tail`),
   and the single-writer append path truncates it (`heal_torn_tail`) so the
   segment self-heals on the next durable event. Any newline-terminated
   garbage line, oversized tail, or torn tail in a non-active segment stays
   hard corruption. Tests:
   `torn_tail_from_a_killed_writer_is_tolerated_and_healed_on_next_append`,
   `torn_tail_outside_the_active_segment_stays_an_error`,
   `garbage_complete_line_is_still_hard_corruption`.

2. **Partial ledger import duplicated on re-import.** `import_ledger_jsonl`
   minted a `ledger-<uuid>` run id; a timeout-killed import left K durable
   rows under a dead `running` run, and re-import re-inserted every row under
   a fresh run (projected ids are scoped by run id). Fixed with
   content-addressed import run ids (`ledger_import_run_id` =
   hash(tool label, ledger bytes)): a re-import replays the same run and the
   same projected finding ids, healing the partial state in place and closing
   the run lifecycle (event-sourced lifecycle takes the latest event). Test:
   `reimport_after_a_killed_partial_import_heals_instead_of_duplicating`.

### Residual (accepted)

- `queue.json`/`plan.json` renames are not fsynced (data + rename ordering is
  guaranteed against process death, not power loss). The v3 event log — the
  artifact that carries findings truth — does fsync file and directory.
- Campaign `events.jsonl` and prompt/scope side files are non-atomic appends/
  writes; both are regenerable or advisory.

## Item 5 — Cost accounting and budget guards

Audited every model-cost read/sum: `trace.jsonl` folds (`budget.rs`
`live_run_spend_usd` and settlement-time `trace_cost.rs` — both parse the
typed `RunTraceStep`, so the snake_case `cost_usd` schema is enforced by
serde and a camelCase-misread-$0 fold is structurally impossible),
`summary.json` (settle prefers `summary.cost_usd`, else the live trace —
never both), the campaign snapshot/trend/ci folds (single source:
`queue.json` `costUsd`, camelCase per that document's serde contract), the
run-summary LLM call ledger (invariant: `cost_usd` XOR `observed_cost_usd`
per call — the done-row double-count trap is guarded), and IEEE `-0.0`
normalization (`+ 0.0` in every sum; verified in the new accumulator too).

### Hole found and fixed

**Per-attempt `costUsd` overwrite undercount.** `apply_transition` set
`entry.cost_usd = cost` on every settle, so a multi-attempt job reported
only its LAST attempt's spend — all earlier attempts' real money vanished
from `total_cost_usd`, the campaign `--budget` gate, the cockpit burn bar,
trend `cost per confirmed`, and `ci` spend. Fixed with
`accumulated_job_cost(prior, attempt)`: each settle adds its attempt's cost
exactly once (settle runs once per dispatched child, including the
shutdown drain path); costless attempts leave the accumulator untouched;
`-0.0` normalized. `resume` already preserved cost history, so
accumulation continues across resumes.

Tests: `accumulated_cost_adds_each_attempt_once_and_skips_costless_attempts`
and the property-style
`queue_total_equals_the_sum_of_all_attempt_costs_exactly_once` (synthetic
multi-attempt, multi-job campaign; queue total must equal the sum of every
attempt cost exactly once).

## Item 6 — claude-cli bridge (`scripts/claude-cli-bridge.mjs`, untracked)

Fixes are also logged in the file's header comment (it is untracked).

- **Argument construction: safe.** `spawn(bin, args)` with an argv array and
  no shell; the prompt travels over stdin, the system prompt via a temp
  file. No interpolation surface.
- **Debug-log redaction (fixed).** Error messages (and therefore
  `~/.kuzushi/bridge-debug.log`) embedded up to 4000 chars of the CLI's raw
  stdout — which is model result text carrying scanned proprietary source
  and finding details — on `exited N`, `produced no JSON`, and
  `claude CLI error` paths. Policy now enforced at one boundary
  (`describeFailure`): stderr diagnostics stay (capped 2000), stdout bodies
  are reduced to a byte count, `KUZUSHI_BRIDGE_LOG_RAW=1` opts back into raw
  bodies for debugging.
- **Env scrubbing (fixed).** Only literal `noop`/`placeholder` API keys were
  stripped; a stale real `ANTHROPIC_API_KEY` silently overrode Vertex ADC
  auth. Now any key is stripped when `CLAUDE_CODE_USE_VERTEX` is on
  (no-silent-fallback). Everything else intentionally passes through — the
  local CLI needs the Vertex/ADC vars, and `--bare` already skips
  hooks/plugins/settings.
- **Truncated-success (fixed).** `error_max_turns` returned `ok:true` with
  `structured` parsed from a cut-off transcript — a truncated triage could
  masquerade as an authoritative verdict. Now: structured-contract requests
  fail with `error_class=provider_response_invalid` (spend disclosed);
  plain-text queries keep `truncated: true` and no longer return
  `structured`.
- Verified offline: `node --check` plus preflight/parse smoke tests pass.

## Item 7 — Watcher storm

Root cause: the notify watcher recursively watches the target root including
`.kuzushi/v3/`, and `runtime_state_path` classified **everything** under it
as a state-artifact event. A headless scan writing into the same workspace
generates one fsync'd event-log segment append, WAL touches, content-store
blob writes, and live `trace.jsonl` appends *per observation* — each one
woke the shell (the wake itself is coalesced, but every drain re-armed the
debounce and refreshed every ~150 ms for the whole scan, pinning a core).
Source-change classification already ignored `.kuzushi` and the TUI already
had drain caps + overflow markers; the hole was state-event classification.

Fix (core `incremental_index/watcher.rs`):
- `.kuzushi/v3/runs/**` no longer classifies — except the terminal
  `done.json` sentinel (one event per run).
- `.kuzushi/v3/log/**` (event-log segments) and `.kuzushi/v3/objects/**`
  (content blobs) no longer classify — per-write internals.
- All sqlite side files (`-wal`, `-journal`, and the previously excluded
  `-shm`) are dropped; the projection main `*.sqlite3` still signals store
  changes on WAL checkpoint, and `queue.json`/`plan.json`/reports/config
  transitions still surface. (This deliberately reverses the earlier
  "keep WAL changes" decision — the WAL is exactly the flood.)

Tests: `store_write_burst_produces_no_watcher_work` (1000 synthetic
churn events classify to zero changes and zero state events; `done.json`
and `queue.json` still surface) and, TUI-side,
`state_event_burst_folds_into_a_single_debounced_refresh` (500 state
batches drain to exactly one applied refresh after the trailing-edge
debounce window, none inside it).

## Item 8 — Panic surface on untrusted input

Swept the long-running/priority surfaces for the ENAMETOOLONG /
GIT_STDOUT_LIMIT failure classes (unwrap/expect, indexing, byte-slicing,
parse-unwrap) with test-module-aware classification:

- **Importers** (ledger JSONL, Burp XML, HAR): tolerant-parse by design;
  every production hit was test fixture code. `chunk[0]` in burp base64 is
  guarded by `chunks()` non-emptiness.
- **Artifact re-parsers** (run summaries, campaign snapshot/trend folds,
  storage_v3 projection payloads): zero production unwraps; malformed
  `queue.json`/`plan.json` are typed context errors.
- **Scanner-output parsers** (semgrep/native engines): clean.
- **Pack/shard TOML** (`shards.rs`, pack module): clean.
- **TUI text pipeline**: every truncation/wrap helper is
  `char_indices`/display-width based — byte-boundary UTF-8 panics on
  untrusted finding titles are structurally impossible; the two raw slices
  in `empty_state_panel`/`prompt` use `find()`-derived boundaries.
- **notify event folding**: `paths[0]`/`paths[1]` guarded by `len() >= 2`.
- All parse-`unwrap()` matches across core/cli/tui (92) classified: every
  one is inside a test module.

The one real "unparsable disk input kills the process/store" hole found in
this audit was the v3 event-log torn tail (a hard error on every subsequent
open) — fixed under Item 4 with typed, scoped recovery. No additional
production panics to convert; no code changes needed beyond Item 4's.

## Item 9 — Findings-output injection (SARIF / Markdown / CI)

- **SARIF structure: safe at the serialization boundary.** The document is
  built with serde (`json!`) — titles/messages are data, never structure.
  New regression:
  `hostile_finding_text_cannot_break_sarif_structure_or_forge_results`
  (a message carrying JSON-closing braces, a newline, and an OSC-52
  escape round-trips as one result with the text intact).
- **`report:sarif` output containment (fixed).** The executor raw-joined
  its `output` path (absolute passthrough, no `..`/symlink checks). Now
  routed through `resolve_contained_output_path` like the other export
  sinks (the descriptor was already `.target_write()` at the registry
  boundary; this closes the direct-executor gap). Test:
  `sarif_output_outside_the_workspace_is_rejected`.
- **JSONL/CSV exports: structure-safe by construction.** JSONL rows are
  serde-serialized (newlines in strings are escaped — no forged rows); CSV
  goes through the `csv` crate (RFC-4180 quoting).
- **Markdown bundle/PR comment:** `escape_md` escapes `|` and folds
  newlines on every interpolated title/description/label — no table-row or
  block forging. Inline markdown *styling* inside titles still renders
  (cosmetic, accepted).
- **Terminal escapes: already hardened.** `sanitize_for_plain_output`
  strips all control chars (C0/DEL/C1) with hostile-title tests, and a
  ratatui canary test pins the framed path's control-char filtering.
- **CI gate severity (disclosure added).** Severity is a typed enum —
  a crafted severity string degrades to `Unknown` at the parse boundary
  and cannot rank above the threshold, so the gate cannot be tripped
  *closed* falsely; `Unknown` never blocks (documented rank rule), and that
  pass is now loud: `ci: PASS … warning: N new confirmed finding(s) carry
  unknown severity and can never trip the gate`.

### Residual (accepted)

- CSV formula injection (`=…` cells opened in spreadsheet apps) is not
  neutralized; exports are operator-consumed artifacts, and mangling data
  with `'` prefixes was judged worse. Revisit if exports ever feed
  third-party ingestion.

## Item L1 — Post-mortem reconstructability

Scenario walkthroughs (artifacts only):

1. **Child killed by the budget guard.** dispatcher.log carries the kill
   line with run id and live spend; events.jsonl records the `over-budget`
   transition (tsMs, jobId, runId, exitCode:null, park reason); the child's
   stdout+stderr are durable in `campaigns/<id>/logs/<runId>.log`; the run's
   `trace.jsonl` (torn-tail tolerant) shows spend up to the kill; no
   `done.json` = honestly non-terminal. Fully reconstructable.
2. **Dispatcher SIGKILLed mid-campaign.** events.jsonl ends without
   `dispatch-end`; rows stay `running`; job children die with the guard
   (Item 3) so their logs stop at the kill. **Gap fixed:** recovery used to
   flip rows silently in queue.json — the next `QueueStore::open` now
   appends a `recovered-stale-running` event per row with the orphaned run
   id, so the timeline explains itself. Test:
   `dead_dispatcher_recovery_is_recorded_in_the_event_log`.
3. **Run died before done.json.** Run dir holds run.json/trace.jsonl; the
   jobs registry renders the disk `running` row as Stale ("running?"); the
   queue recovery event (above) closes the loop for campaign-owned runs.

Correlation: run ids are `<campaign>-<job>-a<dispatch>` and appear in
queue.json rows, every events.jsonl transition detail, the per-attempt log
filename, and the `.kuzushi/v3/runs/<runId>/` artifact dir — grep-by-run-id
works across all files. Child stderr is durable (piped to the attempt log,
never terminal-only). Timestamps: epoch-ms UTC (`tsMs`) in events.jsonl,
`started_at_ms` in trace steps, ISO-UTC in the bridge debug log; monotonic
within a file up to wall-clock steps (no monotonic-clock field — accepted).

## Item L2 — Sensitive content in logs

Findings (mostly already-correct designs, now documented as policy in
OPERATOR.md §8.1):

- **trace.jsonl does NOT persist prompts/completions** — `TracedRuntime`
  records model/provider/latency/cost plus `prompt_len` and `prompt_hash`
  only. Verified in `runtime/traced_runtime.rs` and the `RunTraceStep`
  schema.
- **`.kuzushi/` is proof-excluded from the target's git**, not merely
  gitignored: init runs `git check-ignore` probes over generated state
  paths (runs, log, objects, sqlite, worktrees) and fails loudly if any is
  trackable, while proving `scope.toml`/prompts/config stay visible
  (`workspace_state_initialization/git_policy`). `git add -A` in the
  scanned repo cannot commit triage transcripts.
- **bridge-debug.log** redaction implemented under Item 6 (byte-count
  summaries, `KUZUSHI_BRIDGE_LOG_RAW=1` opt-in).
- **Campaign child logs** stay full-fidelity by policy — they live inside
  the git-proof-excluded `.kuzushi/v3` state dir, the same sensitivity
  boundary as the findings store they describe.
- **Panic messages** may carry workspace paths (not source snippets);
  accepted for an operator-local tool.

Per-artifact policy table documented in OPERATOR.md §8.1.

## Item L3 — Growth, rotation, and error-swallowing

Append-only inventory and bounds:

| File | Bound |
| --- | --- |
| v3 event-log segments | Hard caps (64 MB/segment, 512 MB total, 1 M events, 4096 segments) with explicit errors + compaction event kind. Pre-existing. |
| campaign `events.jsonl` | **Was unbounded — fixed:** one-generation rotation at 16 MB (`events.jsonl` → `.jsonl.1`). Test: `oversized_event_log_rotates_one_generation_before_appending`. |
| `~/.kuzushi/bridge-debug.log` | **Was unbounded — fixed:** one-generation rotation at 5 MB in the bridge. |
| `dispatcher.log` | Truncated on every launch (`File::create`). Pre-existing. |
| per-attempt `<runId>.log` | Fresh file per dispatch; size bounded by the job timeout; count bounded by the never-reset dispatch counter. |
| `trace.jsonl` | Bounded by run lifetime; `runs prune` handles retention. |
| `trend-history.jsonl` | 90-snapshot window (the reference behavior). |

Error-swallowing sweep over the store/sentinel/watcher paths: every
`let _ =`/`.ok()` hit classified — terminal teardown, actor reply-receiver-
dropped, and the failed-run double-fault fallback (primary error still
propagates). Sentinel publish failures already print a visible warning;
watcher errors escalate to conservative full-invalidation markers instead
of being dropped. One accepted best-effort: directory `sync_all` after a
successful file fsync (power-loss ordering only).

## Item P1 — Store hot paths

Fixed the known 40 ms/row import term: `finding_observations` now carries
expression indexes on `json_extract(finding_json, '$.id')` and
`'$.fingerprint'` plus a partial `run_id` index (created idempotently on
every open, so existing databases pick them up). The per-insert
`v3_finding_by_projected_id` lookup, `v3_finding_by_fingerprint`, the
triage projection UPDATE, `finding_ids_for_fingerprint`, and
`v3_findings_for_scan_id` all share those exact expression shapes.
Query-plan regression test:
`projected_id_and_fingerprint_lookups_use_expression_indexes`.

Sweep of remaining `json_extract` sites: `review_decisions.rs` extracts
over a bound `json_each` parameter (in-memory, not a table scan); the
global projection CTE already has its no-correlated-subquery plan test.
No remaining per-row session opens (the batched-import fix predates this
audit) and no chain re-verification in insert loops (one
`StorageWriterSession` per batch).

Release harness rerun recorded in `perf-baseline.md` (aggregate numbers
unchanged at 1k rows — that harness is fsync-bound; the index removes the
term that grew with history size, and the plan test pins it).

## Item P4 — Re-parse and polling economics

- **Budget-guard poll (fixed — the confirmed O(n²)).** `live_run_spend_usd`
  re-read and re-parsed the entire trace.jsonl every 2 s, so a long job's
  cumulative polling cost was quadratic. The dispatcher now uses
  `LiveSpendPoller`: it remembers the byte offset of the last complete
  line, folds only appended tails, defers newline-less torn tails until
  their newline lands, and reports the last known total on read errors.
  Test: `incremental_poll_over_100k_line_trace_reads_only_the_tail` —
  a 100k-line (4-hour-scale) trace folds once, then steady-state polls
  are asserted under 5 ms each and torn appends defer/fold correctly.
  The settlement-time fallback still uses the strict full fold (runs once).
- **Deck/status re-reads: justified as cheap.** `campaign:status` and the
  deck fold read `plan.json` + `queue.json` only (measured 57 ms at 1k
  rows, dominated by the store load, in perf-baseline.md); refreshes are
  event-driven and debounced after Item 7, not per-write.
- **Dispatcher queue re-reads: none.** `QueueStore` holds the document in
  memory and republishes atomically per transition; it never re-parses
  `queue.json` between transitions.
