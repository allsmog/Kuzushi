# Cancellation & failure-path fixes (F1–F7): adversarial review + follow-up plan

Reviewed: uncommitted working tree, 2026-07-09 (Fable 5 review).
Scope: F1 liveness probe / PID stamping, F2 steer-queue drain on abort, F3
watchdog synthetic-fail, F4 failed-tool cost, F5/F7 quiet scan cancel +
partial findings, F6 completion-banner wording, and the `jobs_registry`
test expectation change.

Verification done during review: `cargo check -p kuzushi-core -p kuzushi-tui`
clean; all 24 new/updated targeted tests pass **on darwin** (this machine),
including `liveness_tests::*` (real `kill(pid,0)` leg) and
`jobs_registry_model_downgrades_orphaned_running_summary` with `u32::MAX`.

---

## Part 1 — Adversarial review

### Verdict summary

| Fix | Verdict |
| --- | --- |
| F1 liveness probe + PID stamping | Sound. Known-limitation notes only. |
| F2 steer-queue drain on abort | Fix itself sound; **the invariant it claims is still violated by the planning queue and by chain-advance after cancel** (D2). |
| F3 watchdog synthetic-fail | Slot accounting is race-safe; **interaction with F5 mislabels a hung scan as "canceled"** (D3); escalation does not cover operator-initiated aborts (gap). |
| F4 failed-tool cost | Sound. Correctly scoped; no double-count. Minor asymmetries noted. |
| F5/F7 quiet cancel + partial findings | **Real defect: partial-findings count is the whole store, not this run** (D1). Genuine-crash path preserved byte-for-byte. |
| F6 banner | Correct in itself; contradicted by post-cancel chain/plan advance (part of D2). |
| jobs_registry test `cfg!(unix)` split | Correct on linux, darwin, and windows. |

### Confirmed defects

#### D1 (medium) — Canceled-scan "partial findings retained" counts the entire store, not this run

- `crates/kuzushi-tui/src/app/scan/start_scan/scan_failure_events.rs:74-81`
  (`count_store_findings`) uses
  `FindingListFilter::with_limit(0)` — no `run_id` filter. Verified in
  `crates/kuzushi-core/src/findings/persistence/open/finding_lists.rs:15-36`
  that `report.count` counts **every matching finding in the store**, across
  all runs (`limit` only bounds the returned rows).
- Failure scenario: target already holds 12 findings from a previous scan.
  Operator starts a new scan and cancels it before any new finding lands.
  The shell reports "canceled — 12 partial findings retained", sets
  `scan.findings_count = 12` (`mark_scan_canceled`,
  scan_failure_events.rs:53-55), and stamps `findings: Some(12)` into the
  canceled run's `run.json` (`write_interrupted_scan_summary`,
  scan_failure_events.rs:176-188). Three fabricated claims about a run that
  produced zero findings — a direct violation of the honest-state rule the
  fix itself cites.
- The new unit test (`abort_caused_scan_failure_surfaces_retained_partial_findings`)
  masks this: it seeds a fresh store containing only the canceled run's
  findings, so store-count == run-count.
- Fix: count with `FindingListFilter { run_id: vec![run_id], limit: 0, .. }`
  (the filter already supports `run_id`), and verify the internal
  `sast:scan` pipeline persists findings under the same run id the scan
  panel carries; add a test with pre-existing findings from another run.

#### D2 (medium) — "Stop means stop" invariant still violated by the planning queue and chain-advance

F2 correctly drains the **steer** queue on `request_active_abort`
(`crates/kuzushi-tui/src/app/state_transitions/exit_requests.rs:27-56`), but
the other two "next tool" mechanisms (which the F2 comment itself ranks
*above* steer: chain → plan → steer) still dispatch fresh work after a
full-stop abort:

- `crates/kuzushi-tui/src/app/tool_runner/run_tool/events_and_results.rs:152-157`:
  a canceled planning-driven tool's terminal `Failed` event calls
  `fail_planning_task`, which ends in `resume_or_advance_planning_queue`
  (`crates/kuzushi-tui/src/app/onboarding/runner.rs:379-436`) — it
  dispatches the next *independent* planning task **unconditionally**, with
  no abort check. Scenario: phase walker is running its whitebox queue;
  operator hits Ctrl+C during task 2; task 2's worker honors the token and
  emits `Failed`; the walker logs "no queued task depended on it;
  continuing" and launches task 3 seconds after the operator said stop.
- `events_and_results.rs:60-61` (`apply_finished_tool_event`): a tool that
  ignores the cancel token and **completes** still runs
  `advance_chain_after_tool` + `advance_planning_queue_after_tool` even when
  `state.abort_requested` is true. So the F6 banner honestly says
  "completed after cancel" while the shell simultaneously launches the next
  chained/planned tool — the two signifiers disagree with the behavior.

Both paths are pre-existing (not introduced by this diff), but the F2
change's stated invariant — "a full-stop abort must not leave queued work
behind" — is now half-true, which is worse for operator trust than being
uniformly absent. Severity medium; fix plan in Part 2, item 2.

#### D3 (low-medium) — Watchdog-hung scans are reported through the operator-cancel path

- Chain: watchdog timeout → `mark_scan_timeout` sets
  `scan.abort_requested = true`
  (`crates/kuzushi-tui/src/app/workers/worker_lifecycle/shell_app_timeouts.rs:117-123`)
  → 30s grace → F3 synthetic `ScanEvent::Failed { "worker unresponsive…" }`
  → `apply_scan_failed` → `scan_abort_was_requested()` is true →
  **`apply_scan_canceled`** (scan_failure_events.rs:4-7, 22-24).
- Result: a scan that *hung* (operator never touched anything) ends with the
  panel showing stage `"canceled"`, `scan.error = None`
  (`mark_scan_canceled` clears it), no red notice, and a summary line
  implying an operator cancel. The doc-comment on `apply_scan_canceled`
  says "Operator-initiated abort", but the `abort_requested` flag cannot
  distinguish operator intent from watchdog escalation. The transcript does
  retain the two error-prefixed watchdog lines and the run summary carries
  the true error string, so the state is recoverable — but the primary
  panel/summary signifiers misattribute a hang to the operator.
- Same shape for tools: `mark_tool_timeout` sets the abort flag, so the F3
  synthetic tool failure takes the `log_tool_failure` quiet branch
  (events_and_results.rs:207-218) — no error banner for a hung tool.
- Fix direction: carry an abort *reason* (operator vs watchdog) instead of a
  bare bool; see Part 2, item 3.

### Per-fix adversarial notes (checked and passed)

#### F1 — liveness probe + PID stamping

- **darwin `kill(pid,0)` semantics correct**
  (`crates/kuzushi-core/src/run_artifacts/run_summary_store.rs:205-222`):
  `0` → alive; errno `EPERM` → alive (other-user process); `ESRCH`/other →
  dead. errno is read immediately after the failing call and only when
  `probe != 0` (short-circuit), so no stale-errno window.
- **`kill(-1,0)` aliasing hazard handled**: `libc::pid_t::try_from(u32)`
  rejects anything above `i32::MAX` (so `u32::MAX` — the exact value the
  jobs_registry test persists — returns dead without ever reaching `kill`),
  and the `pid <= 0` guard blocks pid 0 (process-group broadcast). Values in
  `[1, i32::MAX]` that exceed the platform pid range get honest `ESRCH`.
- **Legacy `process_id: None` running summaries are honest**:
  `repair_stale_running_summary` (run_summary_store.rs:167-181) early-returns
  on `None`, so pre-fix rows are never fabricated as interrupted; the jobs
  registry renders them muted `Stale`/"running?" (covered by
  `jobs_registry_model_marks_untwinned_disk_running_row_as_stale`).
- **PID reuse**: if the crashed shell's pid is reused by an unrelated
  process, the row stays "running" on disk and renders `Stale` — the failure
  mode degrades in the honest direction (never a fabricated `interrupted`,
  never a confident green). Inherent to both the `/proc` and `kill` probes;
  hardening option in Part 2, item 6.
- **Repair write is atomic and non-fatal**: a failed rewrite still returns
  the repaired value in-memory; two concurrent listers racing the repair are
  idempotent.
- Minor notes: linux probe returns alive=true when `/proc` is missing
  (honest hedge, but means the linux-leg test assumes procfs);
  `spawn_dead_process_id` has a theoretical pid-reuse flake window
  (negligible on darwin/linux sequential pid allocation); the TUI
  `write_run_summary` stamps the pid **after** `canonical_run_status`
  normalization, so unknown statuses (coerced to "running") are correctly
  stamped too.
- **Cross-platform matrix for the jobs_registry test** (`u32::MAX` orphan):
  linux → `/proc/4294967295` never exists (pid_max ≤ 4194304) → repaired →
  `Interrupted` ✓; darwin/other-unix → `try_from` fails → dead → `Interrupted`
  ✓; windows → `process_is_alive` returns `true` → row stays "running" on
  disk → registry's untwinned-running rule renders `Stale` ✓. The new
  `cfg!(unix)` split is right on all three.

#### F2 — steer-queue drain on abort

- Drain happens in `request_active_abort`, which is reached by **both**
  Ctrl+C (`reduce_quit_chord` → `CancelActiveJobs`) and the `cancel`/`stop`
  verb (command_effects.rs:512) — no verb-shaped bypass.
- Two-stage Ctrl+C preserved: first press cancels + drains (test proves
  `!should_quit()`); second press with abort pending arms/exits without
  re-draining (nothing left to drain).
- Scoped `jobs -k` (`CancelJob(JobKind)`, effects.rs:690-695) intentionally
  does **not** drain — kill-one-job-keep-the-queue is the documented
  Metasploit-style semantics.
- The cost-cap budget guard (`state_transitions/budget_guard.rs:43`) also
  calls `request_active_abort`, so a cost halt now drops queued steer items
  too — correct for a spend cap, and it is logged.
- Items enqueued *after* the abort survive and dispatch on the terminal
  event — reasonable (operator re-queued after saying stop).
- A legitimate non-abort terminal event finding an empty queue is a no-op
  (`advance_steer_queue` pops `None`), so no wrong-dequeue path.
- Remaining gap is D2 above (planning queue / chain, not the steer queue).

#### F3 — watchdog synthetic-fail

- **No resurrect / double-count**: the synthetic `Failed` is a terminal
  event, so `apply_job_event` (runtime_event_drains.rs:46-62) removes the
  slot (`finish(kind)`); every later event from the parked OS thread —
  trace, or its eventual real terminal event — fails
  `is_current_generation` (slot missing) and drains as `Stale`. A new job of
  the same kind gets a fresh generation from the monotonic counter, so the
  parked thread can't poison it either. Stale drains still release the trace
  budget slot (hub.rs:207).
- **Event ordering race safe**: the channel is FIFO. If the worker's real
  terminal event entered the channel before the synthetic fired, the real
  event applies first and the synthetic goes `Stale`; the reverse order
  applies the synthetic and stales the real one — exactly one terminal event
  is ever applied per generation.
- **Generation check on the grace window**: `schedule_unresponsive_escalation`
  no-ops on generation mismatch (hub.rs:126-139); the deadline lives on the
  slot, so slot replacement resets it; `fail_unresponsive_slot` stamps the
  current slot generation, which is by construction the armed one.
- **Channel-full**: `try_send` failure keeps the deadline armed and retries
  next tick — no lost escalation, no busy spin.
- Accepted trade-offs worth naming:
  - A *cooperative-but-slow* worker (cancels honored, cleanup > 30s) gets its
    genuine terminal result discarded as `Stale` and replaced by the
    synthetic "worker unresponsive" failure. Non-terminal progress (live
    trace steps) does **not** disarm or extend the deadline.
  - `WORKER_UNRESPONSIVE_GRACE` is a hardcoded 30s const, not a config knob.
  - Escalation only arms on the **watchdog** path
    (`mark_worker_timeout_requested`). An *operator* abort of a
    non-cooperative worker — or any hang when `worker_watchdog_timeout_ms`
    is `None` — still wedges the slot forever. The original bug survives on
    that path. (Part 2, item 4.)
  - The parked OS thread stays registered in `worker_handles` unreaped until
    process exit; nothing surfaces "N abandoned threads" to the operator.

#### F4 — failed-tool trace-streamed cost

- **Scoping is correct**: `failed_tool_spent_cost_usd` requires
  `state.run_id == session.run_id`. Sessions are recreated per background
  run with the same minted run id passed to `start_tool_run`
  (`tool_runner/run_tool/background.rs:181-188`), so the guard binds the sum
  to the failed run. The stale-session test covers the mismatch case. The
  `default_activity_run_id()` insert path (runtime_event_drains.rs:101)
  produces a mismatching id → billing refused → honest undercount, never a
  misbill.
- **No double-count**: each trace step's `cost_usd` lands on exactly one
  visible DAG row (`apply_activity_row_step`, view_state/activity.rs:806);
  hidden-module steps go to the subsystem aggregate which carries no cost,
  and rolled-up child steps accumulate onto the parent row once. Success
  bills from result-JSON `costUsd` only; failure bills from trace rows only;
  the two paths are mutually exclusive per run.
- Asymmetries (pre-existing, honest-direction, plan item 7):
  hidden-subsystem spend is invisible to the failure sum (undercount); a
  successful tool whose result omits `costUsd` bills $0 even though trace
  rows carry real spend — a failure can bill *more* than an identical
  success; a **canceled scan** (F5 path) records no cost at all even when
  the pipeline burned LLM dollars before the abort.

#### F5/F7 — quiet cancel + partial findings

- Besides D1/D3 above:
- **Genuine crash path preserved byte-for-byte**: the only change to
  `apply_scan_failed` is the two-line early return; the remediation string,
  `RecordScanRun(Failed)`, red notice, structured error log, `result` line,
  and failure handoff are unchanged (and the new
  `genuine_scan_failure_keeps_error_notice_and_remediation` test pins them).
- findings==0 → "no findings were recorded" (no fabricated plural);
  store-open failure → `None` → "partial findings (if any)…" hedge; both
  pinned by `scan_canceled_summary_is_honest_about_counts`. RefreshFindings
  fires with `announce: false` regardless of count — refreshing to an empty
  list is safe.
- `write_interrupted_scan_summary` correctly bypasses the TUI
  `canonical_run_status` (which coerces "interrupted" → "running" — verified
  at artifacts/mod.rs:102-111); it also clears `process_id` via
  `.interrupted()`, so the F1 probe never re-touches a terminal row.
- Wart (low): it constructs a **fresh** `RunSummary::running(...)` and
  overwrites the run's existing `run.json`, resetting `started_at_unix` to
  cancel time (duration reads ~0) and dropping any prior metadata. This
  mirrors the pre-existing TUI `write_run_summary` pattern (completion and
  failure do the same), so it is consistent — but jointly dishonest about
  run duration. Load-and-mutate would fix all three call sites (plan item 1b).
- Wart (low): `record_scan_cancellation_artifacts` does file IO synchronously
  inside the reducer, while the failure path routes IO through the
  `RecordScanRun` effect — side-effects-at-the-edges inconsistency.
- Wart (low): the cancel path emits no `result` transcript line, while both
  success ("ok …") and failure ("fail … exit_hint=1") do — scripted/plain
  consumers that key on a terminal `result` line see nothing for a cancel.

#### F6 — banner

- The wording split is right and tested both ways ("completed after cancel"
  with no ✓ vs. plain "✓ … finished"). The run summary still records
  `completed` (the tool *did* complete) while the DAG row shows Canceled —
  acceptable, since "completed after cancel" is the reconciling banner. The
  real inconsistency is behavioral, not wording: chain/plan advance still
  fires after that banner (D2).

---

## Part 2 — What's next (prioritized)

1. **(P0) Scope the canceled-scan findings count to the run — fixes D1.**
   - Scope: `count_store_findings` takes the scan `run_id` and filters
     `FindingListFilter { run_id: vec![run_id], limit: 0, .. }`; first
     verify the sast:scan pipeline persists findings under the panel's
     run id (if it mints an inner id, plumb the panel id through or map it).
     Keep the `None` hedge for store-open failure. Add a test seeding
     findings under a *different* run id and asserting they are not claimed.
   - 1b (same PR, optional): make `write_interrupted_scan_summary` (and the
     sibling completed/failed writers in `app/artifacts/mod.rs`)
     load-and-mutate the existing summary so `started_at_unix` survives.
   - Files: `crates/kuzushi-tui/src/app/scan/start_scan/scan_failure_events.rs`,
     `crates/kuzushi-tui/src/app/artifacts/mod.rs`.
   - Risk: low. Effort: **S**. Mechanical.

2. **(P0) Extend "stop means stop" to the planning queue and chain — fixes D2.**
   - Scope: gate `advance_chain_after_tool` / `advance_planning_queue_after_tool`
     (finished path) and `fail_planning_task`'s
     `resume_or_advance_planning_queue` (failed path) on
     `state.abort_requested`. For the walker, prefer **pause** over drop —
     it already has a paused vocabulary ("planning queue paused … resume
     with /planning") — so a Ctrl+C pauses the engagement honestly instead
     of silently discarding the phase plan; the steer queue stays
     drop-and-report as shipped.
   - Files: `crates/kuzushi-tui/src/app/tool_runner/run_tool/events_and_results.rs`,
     `crates/kuzushi-tui/src/app/onboarding/runner.rs`,
     `crates/kuzushi-tui/src/app/tests.rs`.
   - Risk: medium (walker resume semantics; make sure a *non-abort* failure
     keeps today's dependency-aware fall-through). Effort: **M**.
     Mostly mechanical; **operator decision**: pause vs drop for the walker
     (recommend pause).

3. **(P1) Abort *reason*, then (maybe) a first-class Canceled terminal state — addresses D3 and F6(a).**
   - Step 1 (recommended now): replace the bare `abort_requested: bool` on
     scan/tool/agent/plan/threat state with
     `Option<AbortReason> { Operator, Watchdog, Budget }`. Route
     `apply_scan_canceled` only for `Operator`/`Budget`; watchdog-escalated
     failures keep an error-severity presentation ("timed out; worker
     unresponsive") while still recording `interrupted` (not `failed`) in
     the summary. Files: `exit_requests.rs`, `shell_app_timeouts.rs`,
     `budget_guard.rs`, `scan_failure_events.rs`, `events_and_results.rs`,
     scan/tool panel state. Effort: **M**, mechanical once the enum exists.
   - Step 2 (separate, larger): first-class `Canceled` below the DAG-row
     layer — new terminal variants on `ToolEvent`/`ScanEvent`
     (`app/jobs/event.rs`), emitted by workers that observe their token, and
     mapped in `apply_job_event`, ActivitySession terminal mapping,
     jobs_registry, renderer/plain. **Do not** add a new on-disk status:
     `RunSummary` already has `interrupted` and the F1 repair path depends
     on that vocabulary — reuse it. Worth doing only after Step 1 proves
     insufficient; today cancel-ness is inferred from flag+string at three
     call sites, which Step 1 already centralizes. Effort: **L**. Risk:
     medium (event-enum churn across workers). **Operator decision** on
     whether the status vocabulary should ever distinguish
     operator-interrupted from watchdog-interrupted on disk.

4. **(P1) F3 hardening: cover operator aborts, respect progress, count parked threads.**
   - (a) Arm `schedule_unresponsive_escalation` from
     `request_scan_abort`/`request_tool_abort`/… too (operator cancel of a
     non-cooperative worker currently wedges the slot forever, and a config
     with `worker_watchdog_timeout_ms = None` has no escalation at all).
     Effort: **S**, mechanical — the hub API already takes (kind, generation, now).
   - (b) Disarm/extend the deadline when a current-generation non-terminal
     event drains (a worker streaming trace steps is not "unresponsive").
     One-line hook in `drain_one`/`apply_job_event`. Effort: **S**.
   - (c) Make the grace a config field (`runtime.worker_unresponsive_grace_ms`),
     not an env var, per the control-surfaces contract. Effort: **S**.
   - (d) Abandoned-thread ledger: when a synthetic fail releases a slot,
     record `(label, generation, since)` in a small registry surfaced by
     `jobs` ("1 abandoned worker thread — restart the shell to reclaim") and
     logged at exit. Honest accounting for the leaked thread. Effort: **M**.
   - (e) The real fix: audit non-cooperative workers for cancellation-token
     polling (long scanner subprocess waits, blocking bridge reads) so the
     synthetic path becomes a last resort. Effort: **L**, investigative.
     **Operator decision** on priority; (a)–(c) are mechanical and cheap.

5. **(P2) Legacy `process_id: None` running summaries.**
   - No honest auto-repair exists (nothing to probe). Leave the default as
     the muted `Stale`/"running?" row (already shipped), and add an explicit
     operator command — e.g. `runs repair` or `jobs --repair-stale` — that
     marks pre-fix `running` rows older than a threshold as `interrupted`
     with an "operator-repaired; liveness unverifiable (no recorded pid)"
     error note. A silent one-time migration would fabricate state and is
     ruled out by the honesty rule. Files:
     `run_summary_store.rs` (+ a CLI/TUI verb). Effort: **S-M**.
     **Operator decision** (it is a UX cleanup, not a correctness need).

6. **(P2) PID-reuse hardening for the F1 probe.**
   - Compare the summary's `started_at_unix` against the probed process's
     start time (linux: `/proc/<pid>/stat` field 22 + btime; darwin:
     `proc_pidinfo`/`sysctl kern.proc.pid`); "alive but started after the
     summary" ⇒ dead ⇒ repairable. Keeps the honest direction while closing
     the immortal-Stale-row window. Files: `run_summary_store.rs` only.
     Effort: **M** (platform code + tests). Mechanical; low urgency since
     the current failure mode is merely a Stale row.

7. **(P2) Cost-accounting symmetry (extends F4).**
   - Success path: fall back to the trace-row sum when the result JSON has
     no `costUsd` (guarded by the same run-id check). Canceled-scan path
     (F5): credit the trace-streamed spend like the failed-tool path does.
     Consider accumulating hidden-module `cost_usd` onto the subsystem
     aggregate row so it is visible and billable. Files:
     `events_and_results.rs`, `scan_failure_events.rs`,
     `view_state/activity.rs`. Effort: **S-M**. Mechanical; add a
     double-count regression test (result `costUsd` present AND trace rows
     present must bill once).

8. **(P3) Test gaps.**
   - EPERM leg: `assert!(process_is_alive(1))` on unix (pid 1 is root-owned;
     unprivileged `kill(1,0)` yields EPERM ⇒ alive). Effort: **S**.
   - Windows: the `#[cfg(not(unix))]` probe and the `Stale` downgrade
     currently compile-only; if a windows CI leg exists, run
     `jobs_registry` + `liveness_tests` there (the `current_process_is_alive`
     test passes trivially, which is the point).
   - F3: a test for the channel-full retry (deadline stays armed when
     `try_send` fails) and a pinning test for the D3 interaction (hung scan
     → current behavior is quiet-cancel) so any future fix is a deliberate
     change.
   - F5: the D1 regression test from item 1; a plain-renderer snapshot for
     the canceled-scan transcript (no `result` line today — pin or fix).
   - Effort: **S** each. Mechanical.

9. **(P3) Reducer purity for the cancel path.**
   - Move `record_scan_cancellation_artifacts` IO behind a
     `RecordScanRun`-style effect (add an `Interrupted { error, retained }`
     outcome to `ScanRunOutcome`), matching the failure path and the
     side-effects-at-the-edges rule. Files: `scan_failure_events.rs`,
     `scan_success_events.rs`, `effects.rs`. Effort: **S-M**. Mechanical;
     also naturally consolidates with item 1b.

### Suggested sequencing

1 (D1, small and shippable) → 2 (D2, the remaining stop-means-stop hole) →
3-step-1 + 4a-c together (one "cancellation semantics" PR: abort reason +
escalation coverage + config knob, which jointly resolve D3) → 5/6/7/8/9 as
capacity allows. Items 3-step-2, 4e, and 5 need an operator decision before
implementation; everything else is mechanical against existing tests.
