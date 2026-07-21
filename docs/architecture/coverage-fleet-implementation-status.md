# Coverage/Fleet implementation status (loop state file)

Implements `coverage-fleet-architecture.md`. This file is the durable state of
the implementation loop: each iteration reads it, does the next unchecked
task, checks it off with a one-line note, and updates NOTES with anything the
next iteration needs. When every milestone is DONE and the final verification
passes, the loop deletes its cron job and this file's status flips to DONE.

Status: **DONE** (started 2026-07-20, completed 2026-07-21; loop cron
10a9b2eb deleted at completion)

## Ground rules (do not re-derive)

- NO git commits. All work stays uncommitted in the tree.
- No hidden LLM subagents; all work in-session.
- Do not touch the campaign-deck WIP (untracked crates/ files, journey.rs
  campaign edits) beyond mechanical conflicts.
- CRAP gate: functions complexity <=4, <40 logical lines, focused tests.
- Follow CLAUDE.md: options via ToolDescriptor first, shared registry
  boundary, plain-renderer parity for any TUI surface, no new env knobs.
- Verify per-milestone with scoped `cargo test -p kuzushi-core <module>` etc.;
  full `cargo build --workspace && cargo test --workspace` only at the end.

## Design decisions already made (verified against the tree 2026-07-20)

- **RevisionRef = existing `RunTargetGitMetadata { sha, branch, dirty }`**
  (`run_artifacts/running.rs:51`), already on `RunSummary.target_git`,
  captured via `workspace/git_metadata.rs::target_git_metadata`. No new type.
- **Coverage ledger store = its own `coverage.sqlite3`** under
  `<target>/.kuzushi/v3/` (NOT the findings DB — that's event-sourced via
  storage_v3; NOT run-history.index.sqlite3 — digest-locked). Open with
  `crate::sqlite_connection::open_file`, WAL + busy timeout like
  `findings/persistence/open/connection_and_schema.rs::configure_connection`.
- **Write chokepoint** = `run_lifecycle/application/terminal_persistence.rs::
  emit_persisted_terminal_outcome_for_call` — after successful
  terminalization, call `coverage_ledger::record_from_summary(target,
  &summary)`; no-op unless summary status is success AND target_git present.
  Ledger write failure must NOT fail the terminal event (log-and-continue).
- Phase mapping tool→phase lives in one pure fn in coverage_ledger
  (map|scan|review|prove|fix; unknown tools → None → no baseline row).
- `kz sweep`: whole-repo `git diff --name-only <sha>..HEAD` once per distinct
  baseline sha (cached in-process), filter per scope path prefix. Never
  pathspec-limited diffs (sweep.py scar).

## M1 — Coverage ledger (task #1) — DONE 2026-07-20

- [x] `workspace/coverage_ledger/{mod,schema,store,summary_intake,sweep,tests}.rs`:
      CoverageLedger (coverage.sqlite3), scan_baselines table, record/latest/all,
      8 tests green.
- [x] Phase mapping: REUSED existing `modules::tool_phase` (descriptor-driven,
      autonomy/tool_phase.rs) — no parallel mapping table. `kind=="scan"` with
      no tool falls back to Scan phase in summary_intake.
- [x] Terminal-event hook: `record_coverage_baseline` in
      run_lifecycle/application/terminal_persistence.rs (after terminal item
      flush; log-and-continue via eprintln). Logic covered by summary_intake
      tests; hook itself is a 5-line adapter (no observation-machinery test).
- [x] `coverage:sweep` + `coverage:baselines` descriptor-backed tools
      (modules/coverage_module.rs, dispatched in dispatch_catalog_tool.rs,
      registered in builtin_registration.rs). Verdicts changed/current/
      baseline-unreachable + unbaselined_scopes; writeSkips option (dirty-tree
      refusal). Headless surface = `kuzushi run coverage:sweep` — no bespoke
      CLI subcommand (options-first rule).
- [x] Findings revision provenance: already derivable — finding rows carry
      run provenance (scan_id/run_id) and RunSummary.target_git has
      sha/branch/dirty; fleet corpus (M3) joins these. No schema change.
- [x] Contract tests updated: policy-inventory fingerprint (reviewed: two new
      tuples coverage:sweep=workspace-write/map, coverage:baselines=read/map)
      + OPERATOR.md "Coverage ledger" section.
- Residue: 27 pre-existing `modules::` test failures are the Node-25 KWP
  permission-mode gap (box has Node 22.9.0) — environmental, untouched.

## M2 — Recommender + TM registry (task #2) — DONE 2026-07-20

- [x] `capabilities/scan_recommender/{domain,fold,gather,tests}` — pure
      `recommend(RecommenderInputs)` fold (never-scanned / phase-gap /
      changed / sink-gap / saturated with scores+evidence) + gather that
      reads ledger (open_if_exists — read tools never create the db),
      sweep (only when ledger exists), build_attack_surface_map.by_file,
      FindingStore file refs. 5 tests green.
- [x] `coverage:recommend` tool (limit option, read policy) — headless
      `kuzushi run coverage:recommend`. Fingerprint + OPERATOR.md updated.
- [x] `resolve_threat_model(target, scope)` in
      threat_model/persistence/registry.rs: scope-file → ancestor-walk →
      persistent-model; scope inputs sanitized (untrusted); 4 tests.
      Deferred: explicit per-scope override key in target config (needs
      untrusted-config gate design), sqlite registry index (YAGNI until the
      TUI needs hydrated listing) — resolver is walk-on-demand.
- [x] Receipt provenance: RunSummary gains threat_model_source +
      threat_model_resolved_via (Option, camelCase, back-compat), populated
      in run_reproducibility_metadata next to the existing
      threat_model_sha256. run_artifacts:: suite green (284).
- [ ] DEFERRED to M5: map-phase NEXT SCANS pane — the fold needs git diffs +
      repo walk, which must NOT run in the frame path; requires an async
      workbench-cache hydration slot like cached_map_artifacts_built.
      Refine op also deferred to M5 (needs git-log delta + finding→threat-ID
      mapping; design in architecture doc §3).

## M3 — Fidelity + fleet local (task #3) — DONE 2026-07-20

- [x] `findings/ingest_contract.rs`: Precondition enum (11 values) +
      severity_ceiling + enforce_severity_ceiling (CappedSeverity w/
      tier_capped); FindingClass closed enum (20) + classify with CWE/keyword
      inference (`inferred` flag); assign_clusters (±15 span-extended,
      file+line only — identity strings are not an input by API design).
      5 unit tests. Existing per-target dedup_key (line/8+CWE) left
      untouched — the ±15 cluster is the cross-target corpus contract.
- [x] Wired at the external-ledger chokepoint: import_ledger_jsonl now caps
      claimed tiers via `contracted_severity` (precondition ceiling in code).
- [x] `tests/fixtures/canary-target/` (3 C plants incl. plant-b calibration
      trap: authed-role command injection claimed P0 → must cap to high) +
      expected-findings.json + tests/canary_fidelity.rs tier-1 (4 tests:
      marker/manifest line lock, ingest ceiling assertions through the REAL
      import path, closed-enum class check, cluster behavior). All green.
- [x] `kuzushi-core::fleet` {registry,corpus,status}: targets.toml
      (idempotent by id, atomic write), corpus.sqlite3 rebuild-and-swap
      (scratch file + rename; per-target FindingStore read-only + run-summary
      revision join; quality_flags class-inferred/no-revision/no-line counted
      never dropped), fleet_status scorecard fold. 5 tests green.
- [x] Tools `fleet:register|ingest|status|findings` (workspace-optional,
      global ~/.kuzushi/v3/fleet) + fingerprint + OPERATOR.md.
- Residue: fleet TUI dashboard deferred to M5 alongside NEXT SCANS pane
      (same async-hydration infrastructure need). Canary tier-2 (LLM e2e)
      already scheduled in M5.

## M4 — Remote plane (task #4) — DONE 2026-07-20

- [x] New crate `crates/kuzushi-fleet` (workspace member, CLI-only binary
      `kuzushi-fleet`; deps anyhow/clap/serde/toml only — zero kuzushi-core
      dependency, transport/judgment split absolute).
- [x] remotes.toml ([[remote]] name/ssh/workdir/slots/session_prefix);
      verbs: doctor (workdir/engine/disk/tmux gate — launch refuses on FAIL),
      stage (pure `stage_guard`: behind-upstream refusal that even --force
      cannot override + live-session refusal; loud-fail scp contract in
      SshTransport), launch (tops up free tmux slots, never doubles),
      status (zombie-aware: pgrep on staged binary vs tmux sessions;
      `healthy()` = the can-I-step-away answer), pull (recency cutoff
      default 24h opt-out via --all, sanitized run names, MANIFEST.json,
      inbox <fleet>/inbox/<box>/<run>/).
- [x] Inbox→corpus path: DECISION — pulled run findings enter through the
      one existing import chokepoint (`workspace:import-findings` into a
      local target registered in the fleet), then `fleet:ingest`. No second
      parser; quality rules stay at one write-time chokepoint.
- [x] 13 unit tests, all against FakeTransport / pure guards — no ssh.
- Deferred to M5 polish: capped-backoff retry loop around launch (v1 fails
      loud instead of retrying; checkpoint-resume is an engine property).

## M5 — Deep fidelity + finish (task #5)

- [x] Guards ledger: coverage_ledger/guards.rs (guards table in
      coverage.sqlite3; blake3 file-hash recorded at write; expiry COMPUTED
      at read — file changed/gone ⇒ row expired; `guard_conflict` ±15-line
      window helper). 3 tests (10 total in coverage_ledger).
- [x] `fleet:diff-findings` (fleet/diff_findings.rs): corpus join across two
      revisions of one target by cluster_id, lead labels
      branch-delta/backport-gap/both, one entry per cluster. Tool wired +
      fingerprint + OPERATOR.md. 1 fold test.
- [x] Session-transcript linter: session_transcript/lint.rs —
      lint_transcript(records): max repeated-log run (watcher-storm signal),
      max stall gap (dependency-free civil-date parse), unfinished runs,
      warning count, `suspicious()` gate. 3 tests. (Budget-burn lint
      deferred: cost lives in run summaries, joinable later.)
- [x] Canary tier-2: documented procedure in
      tests/fixtures/canary-target/README.md (opt-in, engine-version-keyed;
      intentionally not a cargo test — spends LLM).
- [x] FULL VERIFICATION (2026-07-20): workspace build PASS. Test sweep
      results after fixes:
      * MY FIXES: TUI catalog disposition for coverage+fleet (62→2 lib
        failures, all catalog-cascade); snapshot regen via
        KUZUSHI_UPDATE_SNAPSHOTS=1 (26/26 green — 7 files, module-count
        drift incl. concurrent-WIP module additions).
      * GREEN: kuzushi-fleet 13/13, canary_fidelity 4/4, coverage_ledger
        10/10, fleet 5/5, scan_recommender 5/5, lint 3/3, run_artifacts 284.
      * PRE-EXISTING/ENVIRONMENTAL (verified messages, NOT this work):
        27 kuzushi-core + 1 kuzushi-cli Node-25 KWP permission-mode tests
        (box has Node 22.9); kuzushi-tui parity suite needs `tsx` (pnpm
        tooling absent); kuzushi-cli cutover doctor ×2 = this box's global
        model/credential config mismatch; 2 TUI perf/activation tests
        load-flaky (pass in isolation); bdd-tui onboarding 7 cockpit
        scenarios fail in features whose step files are the concurrent
        campaign-deck session's modified WIP (no coverage/fleet mention).

## M6 — TUI surfaces (added so "fully" means fully) — DONE 2026-07-21

- [x] Map-page NEXT SCANS via async hydration:
      `ViewHydrationKey::ScanRecommendations` (Status group) requested only
      while the Map page is active; the reader runs
      `recommend_scans_for_target` (git diffs + repo walk) on the hydration
      worker — never in the frame path. Cache slot in WorkbenchCache with
      invalidation on scan start, state-artifact change, and workspace
      clear. MapPhaseModel gains `next_scans: NextScansState`
      {Pending draws nothing / Ready rows / Unavailable(error)}, rendered
      INSIDE the HOT MODULES pane via one shared `hot_modules_pane_lines`
      builder (grid + compact + plain parity by construction; pane titles
      untouched so the phase-composition contract holds). 3 tests
      (view-model projection, pending-draws-nothing, ready/failed lines).
      Snapshots unchanged (Pending renders nothing without hydration).
- [x] Fleet dashboard: smallest honest increment per CLAUDE.md ("module/
      tool layer before orchestrator internals") — `fleet:status` output IS
      now the one-screen scorecard (header + one row per target: short
      rev/branch/dirty or never-scanned, baselines, xC yH open, flags,
      UNREACHABLE). Identical in shell receipt, `kuzushi run` stdout, and
      plain output because it is the tool's own output. 2 tests. No policy
      change → fingerprint untouched; OPERATOR.md wording already matched,
      added NEXT SCANS clause to the coverage section.
- [x] TM refine op: DEFERRED-DOCUMENTED (architecture doc §3). Data
      contracts shipped in M2 (resolve_threat_model + run-summary
      provenance); refine needs git-log delta + finding→threat-ID mapping
      design and is a new tool (fingerprint + docs) — out of this loop's
      budget, no partial stub shipped.
- [x] Gates re-run 2026-07-21: policy-fingerprint + docs-coverage contract
      tests PASS (no policy tuples changed); registry suite's 25 other
      failures are the documented Node-25 KWP environmental set; full
      kuzushi-tui suite re-run after the concurrent session's transient
      context-module signature break resolved.
- [x] Final verification 2026-07-21: kuzushi-tui lib 2229/2230 (the one
      failure is the documented load-flaky p95 perf test — passes in
      isolation); phase-composition truecolor reference regenerated (the
      map reference frame legitimately gained NEXT SCANS rows; all other
      regen output byte-identical to the pre-regen passing state);
      integration targets snapshots 26/26, activity_dag 9/9, stress 3/3
      (parity target still needs `tsx` — environmental); kuzushi-core
      fleet_module 2/2 new scorecard tests + both registry contract gates
      PASS.

## NOTES (append-only, newest first)

- 2026-07-20: Loop initialized. Tree already carries heavy unrelated WIP
  (campaign deck etc.) — `git status` noise is expected; only verify builds,
  never revert others' modifications.
