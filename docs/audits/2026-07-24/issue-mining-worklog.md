# Issue-Mining Worklog — 2026-07-24

Flattened working evidence from the 2026-07-24 issue-mining session (the
`.audit/` scratch directory, consolidated here verbatim and then removed).
Companion documents:

- The mined issue register (12 Jira-ready issues KZ-1..KZ-12 + 16 held
  candidates) was recorded operator-side outside the repository per
  instruction (`~/KUZUSHI-ISSUES-2026-07-24.md` on the audit box).
- The follow-up execution-truth audit is committed at
  [`docs/assessments/runtime-to-artifact-evidence-integrity-audit-2026-07-24.md`](../../assessments/runtime-to-artifact-evidence-integrity-audit-2026-07-24.md)
  (ETR-001..019; verdict FAIL at 06a3a2a0).

The session tracked a moving upstream: gates were run at `a7cd9d9b` (morning
baseline), re-verified at `63569495` (mid-session pull), and closed at
`06a3a2a0` (final baseline). Every candidate finding was re-verified at the
final baseline before being recorded.

## 1. Audit ledger (kuzushi-issue-mining.jsonl)

**baseline**
```json
{
  "repo": "allsmog/Kuzushi",
  "commit": "a7cd9d9b086f3618c8f9723a4a2eb61fdb3ae45f",
  "branch": "main",
  "clean_tree": true,
  "rustc": "1.96.1",
  "cargo": "1.96.1",
  "node": "v22.22.2",
  "pnpm": "10.30.0 (via npx)",
  "os": "Linux x86_64 6.17.0-1008-gcp",
  "date": "2026-07-24",
  "notes": "gh API cannot see private allsmog/Kuzushi (token=<work-account>); dedupe via git history, remote branches, ROADMAP, docs/audits ledgers"
}
```

**dedupe-source**
```json
{
  "name": "docs/audits/2026-07-22/kuzushi-master-gap-ledger.jsonl",
  "entries": "G1-G31, M1-M14",
  "note": "all excluded as already-tracked"
}
```

**dedupe-source**
```json
{
  "name": "ROADMAP.md",
  "entries": "P0.x-P4.x",
  "note": "roadmap defects may be re-proven at HEAD and promoted only if still live and implementation-ready"
}
```

**gate**
```json
{
  "cmd": "cargo fmt --all -- --check",
  "status": "FAIL",
  "class": "confirmed product defect",
  "detail": "10 files with formatting drift (kuzushi-cli scan_prepare.rs, kuzushi-core structured_output/tests.rs, kuzushi-openai langgraph_runtime/{bridge_process,bridge_process_tests,next_step_bridge,runtime_impl,transport_retry}.rs, kuzushi-tui app/mod.rs)"
}
```

**gate**
```json
{
  "cmd": "cargo check --workspace --all-targets",
  "status": "PASS"
}
```

**gate**
```json
{
  "cmd": "cargo clippy --workspace --all-targets --all-features -- -D warnings",
  "status": "FAIL",
  "class": "confirmed product defect",
  "detail": "5 errors kuzushi-core: unnecessary_sort_by x2 (run_artifacts/stage_checkpoint/discovery.rs:103, runtime/application/loop_checkpoint.rs:120), needless_splitn (threat_model/adapters/build_input.rs:157), dead_code VALID_ACTORS/VALID_STATUSES (threat_model/domain/tool_contract.rs:41,61)"
}
```

**gate**
```json
{
  "cmd": "pnpm check:docs",
  "status": "FAIL",
  "class": "environment",
  "detail": "check-port-contract.mjs required the configured upstream reference remote, which was not present on this box; release contract itself passed"
}
```

**gate**
```json
{
  "cmd": "pnpm quality:architecture",
  "status": "FAIL",
  "class": "confirmed product defect",
  "detail": "11 DDD-boundary violations incl. build_context_snapshot.rs, build_repository_inventory.rs, report/confirmed_sarif.rs, tui renderer failure_coverage.rs/surface_lints.rs, missing agent_chat_lines root"
}
```

**gate**
```json
{
  "cmd": "pnpm quality:model-safety",
  "status": "FAIL",
  "class": "confirmed product defect (gate-red; literals are in #[cfg(test)] fixtures)",
  "detail": "advisories.rs:248, loop_checkpoint.rs:160"
}
```

**gate**
```json
{
  "cmd": "pnpm quality:crap-risk",
  "status": "PASS"
}
```

**gate**
```json
{
  "cmd": "pnpm test",
  "status": "PASS"
}
```

**candidate**
```json
{
  "id": "C-001",
  "title": "main is CI-red at a7cd9d9b: fmt, clippy -D warnings, quality:architecture, quality:model-safety all fail (introduced by 2decb0d3 merge train)",
  "severity": "P1",
  "score_draft": 15
}
```

**final**
```json
{
  "baseline": "06a3a2a0f82079858f5b5a502bee0dce97f1e755",
  "evidence_pass": "63569495c451fbd08f34e6fd32661b68aea0d666",
  "deliverable": "/home/ci/KUZUSHI-ISSUES-2026-07-24.md",
  "filed": 12,
  "held": 16,
  "fixed_during_audit": 3,
  "notes": "upstream moved twice mid-audit; all candidates re-verified at final baseline; no issues created in any tracker per operator instruction"
}
```

## 2. Cargo.lock drift evidence (cargo-lock-drift.diff)

Diff captured when local cargo runs stripped the `git+ssh` source pins for the private oxidized-joern `cpg-*` crates — evidence for the committed-`[patch]`-block finding (fixed upstream in af6bd683 by moving to HTTPS pins).

<details>
<summary>cargo-lock-drift.diff</summary>

```diff
diff --git a/Cargo.lock b/Cargo.lock
index c16324e7..e902c8f6 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -429,7 +429,6 @@ checksum = "773648b94d0e5d620f64f280777445740e61fe701025087ec8b57f45c791888b"
 [[package]]
 name = "cpg-analysis"
 version = "0.1.0"
-source = "git+ssh://git@github.com/allsmog/oxidized-joern.git?rev=9ab43859f0c3342c734ff38ea6366711d216c8fd#9ab43859f0c3342c734ff38ea6366711d216c8fd"
 dependencies = [
  "cpg-core",
  "rayon",
@@ -440,7 +439,6 @@ dependencies = [
 [[package]]
 name = "cpg-cli"
 version = "0.1.0"
-source = "git+ssh://git@github.com/allsmog/oxidized-joern.git?rev=9ab43859f0c3342c734ff38ea6366711d216c8fd#9ab43859f0c3342c734ff38ea6366711d216c8fd"
 dependencies = [
  "cpg-analysis",
  "cpg-core",
@@ -456,12 +454,10 @@ dependencies = [
 [[package]]
 name = "cpg-core"
 version = "0.1.0"
-source = "git+ssh://git@github.com/allsmog/oxidized-joern.git?rev=9ab43859f0c3342c734ff38ea6366711d216c8fd#9ab43859f0c3342c734ff38ea6366711d216c8fd"
 
 [[package]]
 name = "cpg-frontend"
 version = "0.1.0"
-source = "git+ssh://git@github.com/allsmog/oxidized-joern.git?rev=9ab43859f0c3342c734ff38ea6366711d216c8fd#9ab43859f0c3342c734ff38ea6366711d216c8fd"
 dependencies = [
  "cpg-core",
 ]
@@ -469,7 +465,6 @@ dependencies = [
 [[package]]
 name = "cpg-incremental"
 version = "0.1.0"
-source = "git+ssh://git@github.com/allsmog/oxidized-joern.git?rev=9ab43859f0c3342c734ff38ea6366711d216c8fd#9ab43859f0c3342c734ff38ea6366711d216c8fd"
 dependencies = [
  "cpg-analysis",
```

</details>

## 3. Node quality gates at a7cd9d9b (gates-node.log)

`pnpm check:docs` (environmental: missing configured upstream reference remote), `quality:architecture` (11 DDD-boundary violations), `quality:model-safety`, `quality:crap-risk`, `pnpm test`.

<details>
<summary>gates-node.log</summary>

```text
=== GATE: pnpm check:docs ===
[WARN] The "pnpm" field in package.json is no longer read by pnpm. The following keys were ignored: "pnpm.onlyBuiltDependencies", "pnpm.overrides". See https://pnpm.io/settings for the new home of each setting.

> kuzushi@0.24.0-alpha.8 check:docs /home/ci/kuzushi
> node scripts/check-release-contract.mjs && node scripts/check-port-contract.mjs && node scripts/check-public-identity.mjs && node scripts/check-doc-command-drift.mjs && node scripts/check-retired-ts-runtime.mjs

release contract check passed (0.24.0-alpha.8, Rust 1.96.1)
error: No such configured upstream reference remote
Kuzushi port contract check failed:
- configured upstream reference remote is missing; add the documented upstream repository
 ELIFECYCLE  Command failed with exit code 1.

real	0m2.943s
user	0m2.215s
sys	0m0.774s
exit=1
=== GATE: pnpm quality:architecture ===
[WARN] The "pnpm" field in package.json is no longer read by pnpm. The following keys were ignored: "pnpm.onlyBuiltDependencies", "pnpm.overrides". See https://pnpm.io/settings for the new home of each setting.

> kuzushi@0.24.0-alpha.8 quality:architecture /home/ci/kuzushi
> node scripts/check-ddd-boundaries.mjs && node scripts/check-ddd-context-docs.mjs && node scripts/check-artifact-contract.mjs && node scripts/check-result-envelope-contract.mjs && node scripts/check-retired-ts-runtime.mjs && node scripts/check-deferred-surface-contract.mjs && node scripts/check-env-discipline.mjs && node scripts/check-dispatch-boundary-contract.mjs && node scripts/check-run-lifecycle-boundary.mjs && node scripts/check-workspace-state-writes.mjs && node scripts/check-validated-wording.mjs

Kuzushi DDD boundary check failed:
- context builds repository facts without scanner runtime or tool execution: crates/kuzushi-core/src/modules/context/build_context_snapshot.rs
- context builds repository facts without scanner runtime or tool execution: crates/kuzushi-core/src/workspace/inventory/build_repository_inventory.rs
- report boundary reads artifacts and findings without execution: crates/kuzushi-core/src/report/confirmed_sarif.rs
- TUI renderers consume view models without stores or runtime dispatch: crates/kuzushi-tui/src/renderer/failure_coverage.rs
- TUI renderers consume view models without stores or runtime dispatch: crates/kuzushi-tui/src/renderer/phase_composition_contract/failure_snapshots.rs
- TUI renderers consume view models without stores or runtime dispatch: crates/kuzushi-tui/src/renderer/surface_lints.rs
- TUI presentation reads hydrated view data without synchronous artifact IO: crates/kuzushi-tui/src/renderer/failure_coverage.rs
- TUI presentation reads hydrated view data without synchronous artifact IO: crates/kuzushi-tui/src/renderer/phase_composition_contract/failure_snapshots.rs
- TUI presentation reads hydrated view data without synchronous artifact IO: crates/kuzushi-tui/src/renderer/surface_lints.rs
- TUI runtime wording avoids unproven validation claims: crates/kuzushi-tui/src/renderer/failure_coverage.rs
- TUI agent chat renderer reads agent chat view model: no production Rust files matched roots crates/kuzushi-tui/src/renderer/views/chat/agent_chat_lines
 ELIFECYCLE  Command failed with exit code 1.

real	0m7.602s
user	0m3.271s
sys	0m5.007s
exit=1
=== GATE: pnpm quality:model-safety ===
[WARN] The "pnpm" field in package.json is no longer read by pnpm. The following keys were ignored: "pnpm.onlyBuiltDependencies", "pnpm.overrides". See https://pnpm.io/settings for the new home of each setting.

> kuzushi@0.24.0-alpha.8 quality:model-safety /home/ci/kuzushi
> node scripts/check-model-safety.mjs

Kuzushi model safety check failed:
- crates/kuzushi-core/src/capabilities/threat_model/application/staged/advisories.rs:248 hardcoded model field literal
- crates/kuzushi-core/src/capabilities/threat_model/application/staged/advisories.rs:248 hardcoded multiline model field literal
- crates/kuzushi-core/src/runtime/application/loop_checkpoint.rs:160 hardcoded model field literal
- crates/kuzushi-core/src/runtime/application/loop_checkpoint.rs:160 hardcoded multiline model field literal
 ELIFECYCLE  Command failed with exit code 1.

real	0m2.708s
user	0m2.354s
sys	0m0.849s
exit=1
=== GATE: pnpm quality:crap-risk ===
  duration_ms: 0.191431
  type: 'test'
  ...
# Subtest: test in another crate never grants coverage credit
ok 4 - test in another crate never grants coverage credit
  ---
  duration_ms: 0.15246
  type: 'test'
  ...
# Subtest: matching TypeScript test basename grants focused credit
ok 5 - matching TypeScript test basename grants focused credit
  ---
  duration_ms: 1.017309
  type: 'test'
  ...
1..5
# tests 5
# suites 0
# pass 5
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 75.674099
CRAP-risk proxy passed for 0 changed code file(s).

real	0m2.222s
user	0m2.102s
sys	0m0.708s
exit=0
=== GATE: pnpm test ===
> kuzushi@0.24.0-alpha.8 test /home/ci/kuzushi
> node --test scripts/setup-contract.test.mjs

TAP version 13
# Subtest: bootstrap and devcontainer enforce the pinned complete Rust toolchain
ok 1 - bootstrap and devcontainer enforce the pinned complete Rust toolchain
  ---
  duration_ms: 3.43078
  type: 'test'
  ...
# Subtest: devcontainer and doctor share the exact Semgrep dependency pin
ok 2 - devcontainer and doctor share the exact Semgrep dependency pin
  ---
  duration_ms: 1.75122
  type: 'test'
  ...
1..2
# tests 2
# suites 0
# pass 2
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 76.511159

real	0m2.174s
user	0m2.090s
sys	0m0.628s
exit=0
```

</details>

## 4. Rust gates at a7cd9d9b (gates-rust-1.log)

`cargo fmt --check` (10 files drifted) and `cargo clippy -D warnings` (5 errors). Both fixed upstream by the 2decb0d3..63569495 train. ANSI escapes stripped.

<details>
<summary>gates-rust-1.log</summary>

```text
=== GATE: cargo fmt --check ===
Diff in /home/ci/kuzushi/crates/kuzushi-cli/src/application/scan_prepare.rs:168:
             kuzushi_core::progress::HeartbeatGate::new(std::time::Duration::from_secs(5));
         let mut on_files_hashed = |files: usize| {
             if heartbeat.ready() {
-                eprintln!("scan prepare: registering workspace tree identity · {files} files hashed");
+                eprintln!(
+                    "scan prepare: registering workspace tree identity · {files} files hashed"
+                );
             }
         };
         let preparation = kuzushi_core::scan::prepare_scan_workspace_state_with_observer(
Diff in /home/ci/kuzushi/crates/kuzushi-core/src/structured_output/tests.rs:167:
         // through `source()` again made anyhow's alternate formatting print
         // the whole message twice, concatenated — the result-card "429 error
         // shown twice" bug.
-        let source =
-            anyhow::anyhow!("LangGraph bridge failed: Provider rate limited the request (HTTP 429).");
+        let source = anyhow::anyhow!(
+            "LangGraph bridge failed: Provider rate limited the request (HTTP 429)."
+        );
         let error = anyhow::Error::from(StructuredOutputError::from_source_and_cost(
             source,
             crate::runtime::RuntimeCostReport::UNAVAILABLE,
Diff in /home/ci/kuzushi/crates/kuzushi-openai/src/langgraph_runtime/bridge_process.rs:108:
     let Some(detail) = detail.map(str::trim).filter(|detail| !detail.is_empty()) else {
         return message;
     };
-    let bounded = detail.chars().take(MAX_BRIDGE_DETAIL_CHARS).collect::<String>();
+    let bounded = detail
+        .chars()
+        .take(MAX_BRIDGE_DETAIL_CHARS)
+        .collect::<String>();
     format!("{message} — detail: {bounded}")
 }
 
Diff in /home/ci/kuzushi/crates/kuzushi-openai/src/langgraph_runtime/bridge_process_tests.rs:4:
 use super::bridge_process::{
     bridge_near_executable, configure_bridge_process_group, default_langgraph_bridge_command,
     mcp_binary_env_defaults, public_bridge_error, public_bridge_failure_with_detail,
-    read_bounded_pipe,
-    run_next_step_bridge, wait_with_output_deadline_limits,
+    read_bounded_pipe, run_next_step_bridge, wait_with_output_deadline_limits,
 };
 use kuzushi_core::AgentToolPolicy;
 use serde_json::json;
Diff in /home/ci/kuzushi/crates/kuzushi-openai/src/langgraph_runtime/next_step_bridge.rs:48:
         let Some(failure) = failure.filter(|f| attempt < transport_retry::max_attempts(f)) else {
             return Err(error);
         };
-        transport_retry::sleep_before_retry(transport_retry::backoff_delay(attempt, &failure), || {
-            ensure_not_cancelled(runtime)
-        })?;
+        transport_retry::sleep_before_retry(
+            transport_retry::backoff_delay(attempt, &failure),
+            || ensure_not_cancelled(runtime),
+        )?;
     }
 }
 
Diff in /home/ci/kuzushi/crates/kuzushi-openai/src/langgraph_runtime/runtime_impl.rs:7:
 };
 
 use super::bridge_payloads::{BridgeRequest, BridgeResponse, LANGGRAPH_BRIDGE_PROTOCOL_VERSION};
-use super::bridge_process::{
-    public_bridge_error, public_bridge_failure_with_detail, run_bridge,
-};
+use super::bridge_process::{public_bridge_error, public_bridge_failure_with_detail, run_bridge};
 use super::next_step_bridge::next_step_blocking as run_next_step_blocking;
 use super::next_step_bridge::next_step_observed_blocking as run_next_step_observed_blocking;
 use super::next_step_bridge::preflight_tool_loop_blocking as run_preflight_tool_loop_blocking;
Diff in /home/ci/kuzushi/crates/kuzushi-openai/src/langgraph_runtime/runtime_impl.rs:231:
         if attempt >= transport_retry::max_attempts(&failure) {
             return Err(error);
         }
-        transport_retry::sleep_before_retry(transport_retry::backoff_delay(attempt, &failure), || {
-            ensure_not_cancelled(cancellation)
-        })?;
+        transport_retry::sleep_before_retry(
+            transport_retry::backoff_delay(attempt, &failure),
+            || ensure_not_cancelled(cancellation),
+        )?;
     }
 }
 
Diff in /home/ci/kuzushi/crates/kuzushi-openai/src/langgraph_runtime/transport_retry.rs:69:
     let deadline = Instant::now() + delay;
     loop {
         ensure_not_cancelled()?;
-        let Some(remaining) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) else {
+        let Some(remaining) = deadline
+            .checked_duration_since(Instant::now())
+            .filter(|d| !d.is_zero())
+        else {
             return Ok(());
         };
         std::thread::sleep(remaining.min(Duration::from_millis(200)));
Diff in /home/ci/kuzushi/crates/kuzushi-openai/src/langgraph_runtime/transport_retry.rs:185:
         assert!(limited.rate_limited);
         assert_eq!(limited.retry_after, Some(Duration::from_secs(30)));
 
-        assert!(response_transient_failure(Some(401), Some("authentication"), None, None).is_none());
+        assert!(
+            response_transient_failure(Some(401), Some("authentication"), None, None).is_none()
+        );
 
         let flaky = message_transient_failure("socket hang up").expect("transport is transient");
         assert!(!flaky.rate_limited);
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/mod.rs:177:
     skip_onboarding_env, toggle_planning_row, topological_order, transitive_dependencies,
     ArtifactState as PlanningArtifactState, AuthMethodRow, AuthMethodRowKind, FailedPlanningTask,
     InitialOnboardingPhase, LastAttempt, OnboardingInputs, PendingRetry, PickerFocus,
-    PlanningOptionEdit,
-    PlanningOptionOverrides, PlanningTaskId, PlanningTaskRow, RowDisposition, TargetCandidate,
-    TargetCandidateScope, TargetProfile, ToggleOutcome, WorkflowPhase,
+    PlanningOptionEdit, PlanningOptionOverrides, PlanningTaskId, PlanningTaskRow, RowDisposition,
+    TargetCandidate, TargetCandidateScope, TargetProfile, ToggleOutcome, WorkflowPhase,
 };
 pub(crate) use onboarding::{bound_target_candidate, immediate_target_candidate};
 pub use prereq_chain::{
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/onboarding/mod.rs:43:
     discover_target_candidates, record_recent_target, TargetCandidate, TargetCandidateScope,
 };
 pub use task_id::PlanningTaskId;
-pub use task_row::{
-    artifact_state, cli_is_on_path, ArtifactState, LastAttempt, PlanningTaskRow,
-};
 pub(crate) use task_row::overlay_last_attempts;
+pub use task_row::{artifact_state, cli_is_on_path, ArtifactState, LastAttempt, PlanningTaskRow};
 
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/onboarding/recommend.rs:67:
         // Keep first value fast and predictable. These remain visible as
         // deliberate Deep map work instead of silently starting database or
         // model-backed construction from the default plan.
-        BuildThreatModel | BuildStrideThreatModel | BuildCodePropertyGraph
+        BuildThreatModel
+        | BuildStrideThreatModel
+        | BuildCodePropertyGraph
         | BuildCodeQlDatabase => false,
         // Reverse-engineering artifacts only matter for binary/APK targets.
         BuildXRay => target.kind.is_reverse_engineering_target() && missing_artifact(row),
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/onboarding/recommend.rs:111:
         Some(LastAttempt::Failed {
             resumable: true, ..
         }) => Some(true),
-        Some(LastAttempt::Completed)
-            if matches!(row.artifact_state, ArtifactState::Action) =>
-        {
+        Some(LastAttempt::Completed) if matches!(row.artifact_state, ArtifactState::Action) => {
             Some(false)
         }
         _ => None,
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/onboarding/recommend.rs:295:
         assert!(!picked.contains(&PlanningTaskId::VerifyFindings));
         // Dedupe and chain-hunt are offered in the Review picker but never
         // preselected — both are deliberate model-spend opt-ins.
-        let offered = applicable_tasks_for_phase(WorkflowPhase::Review, profile(TargetKind::Source));
+        let offered =
+            applicable_tasks_for_phase(WorkflowPhase::Review, profile(TargetKind::Source));
         assert!(offered.contains(&PlanningTaskId::DedupeFindings));
         assert!(offered.contains(&PlanningTaskId::HuntChains));
         assert!(!picked.contains(&PlanningTaskId::DedupeFindings));
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/onboarding/task_row.rs:171:
 
 fn failed_attempt(target: &Path, row: &PlanningTaskRow, run_id: &str) -> LastAttempt {
     let continuation = kuzushi_core::modules::tool_continuation(row.tool_name);
-    let coordinates =
-        kuzushi_core::run_artifacts::checkpoint_coordinates_for_run(target, run_id);
+    let coordinates = kuzushi_core::run_artifacts::checkpoint_coordinates_for_run(target, run_id);
     let resumable = continuation.is_continuable()
         && (coordinates.is_some()
             || matches!(
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/onboarding/task_row.rs:187:
 
 /// The live threat model's real methodology + ledger version, so the picker
 /// says "cached · stride v4" instead of guessing from the row that built it.
-fn cached_row_detail(
-    task: PlanningTaskId,
-    target: &Path,
-    state: ArtifactState,
-) -> Option<String> {
+fn cached_row_detail(task: PlanningTaskId, target: &Path, state: ArtifactState) -> Option<String> {
     if task != PlanningTaskId::BuildThreatModel || state != ArtifactState::Cached {
         return None;
     }
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/phase_results.rs:394:
             .or_else(|| {
                 let pending =
                     !kuzushi_core::runtime::pending_agent_loop_checkpoints(target).is_empty();
-                pending.then(|| completed.run_refs.last().cloned()).flatten()
+                pending
+                    .then(|| completed.run_refs.last().cloned())
+                    .flatten()
             })
     }
 
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/phase_results.rs:875:
     // Failed runs carry the same error text as both output and error; the
     // card must not print it twice (once as `│ …` preview, once as `⚠ …`).
     // Old ledger records also doubled the message inside one string.
-    let message =
-        operator_message.map(kuzushi_core::run_lifecycle::collapse_repeated_message);
+    let message = operator_message.map(kuzushi_core::run_lifecycle::collapse_repeated_message);
     if let Some(message) = message
         .as_deref()
         .filter(|message| *message != summary)
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/phase_results.rs:1123:
     fn write_stage_checkpoint(target: &std::path::Path, run_id: &str) {
         std::fs::create_dir_all(target.join(".kuzushi")).unwrap();
         std::fs::write(target.join("research.json"), "{}").unwrap();
-        let store =
-            kuzushi_core::run_artifacts::StageCheckpointStore::discover(target, &[5u8; 32])
-                .unwrap();
+        let store = kuzushi_core::run_artifacts::StageCheckpointStore::discover(target, &[5u8; 32])
+            .unwrap();
         let handle = kuzushi_core::run_artifacts::StageCheckpointHandle::open(
             store,
             target,
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/phase_results.rs:1189:
         let mut app = super::super::ShellApp::new(kuzushi_core::V2Config::default(), None);
         app.set_target(Some(temp.path().to_path_buf()));
 
-        let failed = app
-            .phase_result_presentation_for(&attempt_with_outcome(
-                temp.path(),
-                PhaseAttemptOutcome::Failed,
-            ));
+        let failed = app.phase_result_presentation_for(&attempt_with_outcome(
+            temp.path(),
+            PhaseAttemptOutcome::Failed,
+        ));
         assert!(
-            failed.detail_lines.iter().any(|line| {
-                line.contains("resume checkpoint saved (1 completed agent turn)")
-            }),
+            failed
+                .detail_lines
+                .iter()
+                .any(|line| { line.contains("resume checkpoint saved (1 completed agent turn)") }),
             "failed result must disclose the checkpoint: {:?}",
             failed.detail_lines
         );
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/session/handle_context_command/load_resume_pause.rs:113:
     /// A run can be resumed when it ended without completing (failed,
     /// interrupted, or canceled) and recorded the tool + input it was
     /// dispatched with. Anything else is inspect-only.
-    fn resumable_run_invocation(&mut self, run_id: &str) -> anyhow::Result<Option<(String, String)>> {
+    fn resumable_run_invocation(
+        &mut self,
+        run_id: &str,
+    ) -> anyhow::Result<Option<(String, String)>> {
         let Some(target) = self.target_owned() else {
             anyhow::bail!("resume requires an active target. Next: target <path>");
         };
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/session/handle_context_command/load_resume_pause.rs:120:
         let summary = kuzushi_core::run_artifacts::load_run_summary(&target, run_id)?;
-        let resumable = matches!(summary.status.as_str(), "failed" | "interrupted" | "canceled");
+        let resumable = matches!(
+            summary.status.as_str(),
+            "failed" | "interrupted" | "canceled"
+        );
         let Some(tool) = summary.tool.filter(|_| resumable) else {
             return Ok(None);
         };
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/state_transitions/key_dispatch.rs:259:
     /// advertised.
     pub(crate) fn phase_result_target_phase(&self) -> Option<WorkflowPhase> {
         let page_phase = crate::ui_view_models::active_workbench_page(self).phase();
-        if self.engagement.unresolved_phase_attempt(page_phase).is_some() {
+        if self
+            .engagement
+            .unresolved_phase_attempt(page_phase)
+            .is_some()
+        {
             return Some(page_phase);
         }
         WorkflowPhase::ORDER
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/state_transitions/picker_keys.rs:1218:
         // detour) go straight back; workbench origins restore their page,
         // since the findings refresh inside `open_workbench` may have
         // re-derived a different one.
-        if let Some(view) = origin_view.filter(|view| {
-            !matches!(view, ShellView::Workbench | ShellView::PlanningPicker)
-        }) {
+        if let Some(view) = origin_view
+            .filter(|view| !matches!(view, ShellView::Workbench | ShellView::PlanningPicker))
+        {
             self.set_shell_view(view);
             return;
         }
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/state_transitions/view_hotkey_actions.rs:90:
                 self.toggle_workbench_investigation_boundary()
             }
             ViewHotkeyAction::WorkbenchDeferProof => self.draft_workbench_proof_deferral(),
-            ViewHotkeyAction::WorkbenchReverifyPatch => {
-                self.draft_workbench_patch_reverification()
-            }
+            ViewHotkeyAction::WorkbenchReverifyPatch => self.draft_workbench_patch_reverification(),
             ViewHotkeyAction::WorkbenchSuppress => self.draft_workbench_suppression(),
             ViewHotkeyAction::WorkbenchInvariantHunt => self.draft_workbench_invariant_hunt(),
             ViewHotkeyAction::WorkbenchOrderChain => self.draft_workbench_chain(),
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/state_transitions/view_hotkey_actions.rs:310:
                 "refine draft loaded — Enter to update the stale threat model",
             )
         } else {
-            ("next", "journey planner loaded — Enter to continue the derived phase")
+            (
+                "next",
+                "journey planner loaded — Enter to continue the derived phase",
+            )
         };
         self.set_input(command.to_string());
         self.set_input_mode(InputMode::Prompt);
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/state_transitions/view_hotkey_actions.rs:608:
 
     /// Item 13: `/` opens the palette-style search capture over the queue.
     fn open_review_search(&mut self) {
-        self.router.workbench_mut().review_mut().open_search_capture();
+        self.router
+            .workbench_mut()
+            .review_mut()
+            .open_search_capture();
         self.log(
             "review",
             "search: type to filter · sev:/tool:/status:/actor: facets · Enter keep · Esc clear",
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/tests.rs:14824:
 
     let mut live = load_persistent_threat_model(&target).unwrap();
     assert!(
-        live.as_object_mut().unwrap().remove("verification").is_some(),
+        live.as_object_mut()
+            .unwrap()
+            .remove("verification")
+            .is_some(),
         "threats use <n> re-verifies the restored document"
     );
     assert_eq!(live, original);
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/tests.rs:21042:
         &mut app,
         KeyEvent::new(KeyCode::Char('1'), KeyModifiers::empty()),
     );
-    assert_eq!(app.input(), "model 1", "draft typing must win over tab keys");
+    assert_eq!(
+        app.input(),
+        "model 1",
+        "draft typing must win over tab keys"
+    );
     assert_eq!(app.router.threat().view(), ThreatView::Stride);
 }
 
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/app/view_state/activity.rs:2292:
 
         let mut inherited = ActivitySession::new("run-3");
         inherited.seed_task_sequence(["secrets:scan[deep]".to_string()]);
-        inherited.tasks.get_mut("secrets:scan[deep]").unwrap().prior_run_ref =
-            Some("run-2".to_string());
+        inherited
+            .tasks
+            .get_mut("secrets:scan[deep]")
+            .unwrap()
+            .prior_run_ref = Some("run-2".to_string());
         inherited.alias_tool_to_unique_planned_row("secrets:scan");
         inherited.mark_task_partial("secrets:scan", "x");
         // The only match belongs to a prior run → no alias (item 5c keying).
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/boundary_lints.rs:25:
     // PATH / HOME process integration.
     "app/tool_runner/run_tool/background/preflight.rs", // PATH
     "app/onboarding/task_row.rs", // PATH + KUZUSHI_CODEQL_BIN CLI presence probe
-    "ui_view_models/home_cockpit.rs",                   // HOME for ~ display
+    "ui_view_models/home_cockpit.rs", // HOME for ~ display
     // Compatibility adapter reads (documented in CLAUDE.md).
     "app/shell_lifecycle/construction.rs", // ui.auto_open_viz compat value
     // Test / devex hooks.
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/renderer/views/onboarding/planning_picker.rs:839:
             resume_from: None,
         } => Some("continue from checkpoint".to_string()),
         LastAttempt::Failed { .. } => Some("failed last pass".to_string()),
-        LastAttempt::Completed
-            if matches!(row.artifact_state, PlanningArtifactState::Action) =>
-        {
+        LastAttempt::Completed if matches!(row.artifact_state, PlanningArtifactState::Action) => {
             Some("done this pass".to_string())
         }
         LastAttempt::Completed => None,
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/renderer/views/scene/diagram/dfd.rs:263:
         };
         match dfd_selected_item(&self.model, selected) {
             Some(DfdSelected::Node(node)) => {
-                text(buf, area, 2, y, &format!("▸ {}", node.name), selection_color());
+                text(
+                    buf,
+                    area,
+                    2,
+                    y,
+                    &format!("▸ {}", node.name),
+                    selection_color(),
+                );
                 text(buf, area, 2, y + 1, &node_detail(node), diagram_muted());
             }
             Some(DfdSelected::Flow(flow)) => {
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/renderer/views/scene/diagram/dfd.rs:319:
 
 /// Anchors keyed by node name (flows reference display names) for the
 /// visible placements only — flows to a paged-out node are simply skipped.
-fn anchor_map(
-    model: &DfdModel,
-    placements: &[NodePlacement],
-    nbw: u16,
-) -> HashMap<String, Anchor> {
+fn anchor_map(model: &DfdModel, placements: &[NodePlacement], nbw: u16) -> HashMap<String, Anchor> {
     placements
         .iter()
         .map(|placement| {
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/renderer/views/scene/diagram/dfd.rs:400:
 
 fn flow_detail(flow: &DfdFlowModel) -> String {
     let boundaries = if flow.boundary_ids.is_empty() {
-        if flow.crosses { "crosses boundary" } else { "in-zone" }.to_string()
+        if flow.crosses {
+            "crosses boundary"
+        } else {
+            "in-zone"
+        }
+        .to_string()
     } else {
         format!("boundaries: {}", flow.boundary_ids.join(", "))
     };
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/renderer/views/scene/diagram/dfd.rs:584:
             24,
         );
         assert!(node_selected.contains("▸ web"), "{node_selected}");
-        assert!(node_selected.contains("process · zone a"), "{node_selected}");
+        assert!(
+            node_selected.contains("process · zone a"),
+            "{node_selected}"
+        );
 
         let flow_selected = render_to_text(
             DfdDiagram {
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/renderer/views/threat/threat_lines/stride.rs:1:
 use super::*;
-use crate::ui_view_models::{
-    SeverityTone, ThreatStrideMember, ThreatStrideRow, ThreatStrideTone,
-};
+use crate::ui_view_models::{SeverityTone, ThreatStrideMember, ThreatStrideRow, ThreatStrideTone};
 
 pub(super) fn append_stride_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
     let rollup = crate::ui_view_models::threat_stride_rollup(app);
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/renderer/views/threat/threat_lines/stride.rs:21:
     Line::from(vec![
         Span::raw("        "),
         Span::styled(pad(&member.id, 6), theme::primary()),
-        Span::styled(pad(&member.severity, 10), threat_stride_tone_style(member.tone)),
+        Span::styled(
+            pad(&member.severity, 10),
+            threat_stride_tone_style(member.tone),
+        ),
         Span::styled(fit(&member.title, title_w), theme::muted()),
     ])
 }
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/renderer/views/workbench/phase_pages/map.rs:227:
 /// noise until the target is broken into scoped modules.
 fn decompose_first_lines(hint: &str, width: usize) -> Vec<Line<'static>> {
     vec![
-        Line::styled(fit("⚠ Large monorepo — decompose before modeling", width), theme::warn()),
+        Line::styled(
+            fit("⚠ Large monorepo — decompose before modeling", width),
+            theme::warn(),
+        ),
         Line::styled(fit(hint, width), theme::muted()),
         Line::styled(
             fit(
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/renderer/views/workbench/phase_pages/map.rs:619:
 
         assert_eq!(title, "NEXT ACTION");
         let rendered = text(&lines);
-        assert!(rendered.contains("suggest module decomposition"), "{rendered}");
+        assert!(
+            rendered.contains("suggest module decomposition"),
+            "{rendered}"
+        );
         assert!(rendered.contains("81259 files indexed"), "{rendered}");
         assert!(!rendered.contains("generate threat model"), "{rendered}");
     }
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/ui_view_models/activity_header.rs:420:
             0,
             Some(190),
         );
-        assert!(model.summary_title.contains("stage 2/4"), "{}", model.summary_title);
-        assert!(model.summary_title.contains("~3m10s left"), "{}", model.summary_title);
+        assert!(
+            model.summary_title.contains("stage 2/4"),
+            "{}",
+            model.summary_title
+        );
+        assert!(
+            model.summary_title.contains("~3m10s left"),
+            "{}",
+            model.summary_title
+        );
 
         let no_history = activity_header_model_with_queue(
             &session,
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/ui_view_models/activity_header.rs:769:
 
         assert_eq!(counts.total, 1);
         assert_eq!(counts.done, 1);
-        assert_eq!(counts.failing, 0, "prior run's failure leaked into the header");
+        assert_eq!(
+            counts.failing, 0,
+            "prior run's failure leaked into the header"
+        );
     }
 
     fn model_cost_step(n: usize, module: &str, verb: &str, cost: f64) -> RunTraceStep {
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/ui_view_models/activity_observability.rs:210:
         session.apply_step(start);
 
         let stale_probe = Instant::now() + Duration::from_secs(45);
-        let model =
-            activity_heartbeat_model(&session, Some("threat-model:build"), true, None, stale_probe);
+        let model = activity_heartbeat_model(
+            &session,
+            Some("threat-model:build"),
+            true,
+            None,
+            stale_probe,
+        );
         assert_eq!(model.tone, ActivityHeartbeatTone::Live, "{}", model.text);
-        assert!(model.text.contains("◐ query in flight 45s"), "{}", model.text);
+        assert!(
+            model.text.contains("◐ query in flight 45s"),
+            "{}",
+            model.text
+        );
         assert!(!model.text.contains("NO PROGRESS SIGNAL"), "{}", model.text);
 
         let watchdog_probe = Instant::now() + Duration::from_secs(400);
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/ui_view_models/findings.rs:797:
     visible
         .into_iter()
         .filter(|(_, index)| {
-            app.findings().get(*index).is_some_and(|finding| {
-                finding_matches_search(finding, &terms, &review_index)
-            })
+            app.findings()
+                .get(*index)
+                .is_some_and(|finding| finding_matches_search(finding, &terms, &review_index))
         })
         .collect()
 }
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/ui_view_models/findings.rs:868:
             .as_deref()
             .is_some_and(|actor| actor.to_lowercase().contains(wanted))
     });
-    let status_ok = terms.status.as_deref().is_none_or(|wanted| {
-        search_status_label(finding, review_index).contains(wanted)
-    });
+    let status_ok = terms
+        .status
+        .as_deref()
+        .is_none_or(|wanted| search_status_label(finding, review_index).contains(wanted));
     severity_ok && tool_ok && actor_ok && status_ok
 }
 
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/ui_view_models/phase_cockpit/map.rs:51:
         tree,
         ViewDataState::Ready(crate::app::ProjectScopeTreeState::RootOnly)
     );
-    undecomposed.then(|| {
-        format!("{files} files indexed — break the target into logical modules first")
-    })
+    undecomposed
+        .then(|| format!("{files} files indexed — break the target into logical modules first"))
 }
 
 const NEXT_SCAN_ROW_LIMIT: usize = 4;
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/ui_view_models/threat_stories.rs:131:
 /// Cross-referencing threat-model.json must work in both directions: when
 /// the listed id differs from the artifact's model-emitted `id`/`stableId`,
 /// disclose them as detail rows instead of leaving the operator to guess.
-fn artifact_id_details(
-    threat: &serde_json::Value,
-    listing_id: &str,
-) -> Vec<ThreatStoryDetail> {
+fn artifact_id_details(threat: &serde_json::Value, listing_id: &str) -> Vec<ThreatStoryDetail> {
     let mut details = Vec::new();
     if let Some(id) = string_field(threat, "id").filter(|id| id != listing_id) {
         details.push(ThreatStoryDetail {
Diff in /home/ci/kuzushi/crates/kuzushi-tui/src/ui_view_models/threat_stride.rs:145:
         matching.len(),
         String::new(),
     );
-    row.members = matching.iter().map(|threat| stride_member(threat)).collect();
+    row.members = matching
+        .iter()
+        .map(|threat| stride_member(threat))
+        .collect();
     row
 }
 

real	0m2.775s
user	0m2.326s
sys	0m0.317s
fmt_exit=1
=== GATE: cargo check ===
15 |     pub(crate) retry: BridgeRetryPolicy,
   |                ^^^^^
   |
   = note: `LangGraphRuntime` has derived impls for the traits `Clone` and `Debug`, but these are intentionally ignored during dead code analysis
   = note: `#[warn(dead_code)]` (part of `#[warn(unused)]`) on by default

warning: constant `MAX_BRIDGE_RETRY_DELAY_MS` is never used
  --> crates/kuzushi-openai/src/langgraph_runtime/runtime_config.rs:30:7
   |
30 | const MAX_BRIDGE_RETRY_DELAY_MS: u64 = 120_000;
   |       ^^^^^^^^^^^^^^^^^^^^^^^^^

warning: methods `attempts` and `delay_ms` are never used
  --> crates/kuzushi-openai/src/langgraph_runtime/runtime_config.rs:55:19
   |
41 | impl BridgeRetryPolicy {
   | ---------------------- methods in this implementation
...
55 |     pub(crate) fn attempts(&self) -> usize {
   |                   ^^^^^^^^
...
59 |     pub(crate) fn delay_ms(&self, attempt: usize) -> u64 {
   |                   ^^^^^^^^

warning: `kuzushi-openai` (lib) generated 3 warnings
   Compiling kuzushi-tui v0.24.0-alpha.8 (/home/ci/kuzushi/crates/kuzushi-tui)
warning: `kuzushi-core` (lib test) generated 2 warnings (2 duplicates)
warning: `kuzushi-openai` (lib test) generated 1 warning (1 duplicate)
    Checking kuzushi-cli v0.24.0-alpha.8 (/home/ci/kuzushi/crates/kuzushi-cli)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 9.63s

real	0m9.875s
user	0m12.406s
sys	0m4.374s
check_exit=0
=== GATE: cargo clippy ===
   --> crates/kuzushi-core/src/capabilities/threat_model/adapters/build_input.rs:157:24
    |
157 |         .filter(|line| line.splitn(2, ',').next().map(str::trim) != Some("id"))
    |                        ^^^^^^^^^^^^^^^^^^^ help: try: `line.split(',')`
    |
    = help: for further information visit https://rust-lang.github.io/rust-clippy/rust-1.96.0/index.html#needless_splitn
    = note: `-D clippy::needless-splitn` implied by `-D warnings`
    = help: to override `-D warnings` add `#[allow(clippy::needless_splitn)]`

error: consider using `sort_by_key`
   --> crates/kuzushi-core/src/run_artifacts/stage_checkpoint/discovery.rs:103:5
    |
103 |     pending.sort_by(|left, right| right.modified_at_unix.cmp(&left.modified_at_unix));
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
    = help: for further information visit https://rust-lang.github.io/rust-clippy/rust-1.96.0/index.html#unnecessary_sort_by
    = note: `-D clippy::unnecessary-sort-by` implied by `-D warnings`
    = help: to override `-D warnings` add `#[allow(clippy::unnecessary_sort_by)]`
help: try
    |
103 -     pending.sort_by(|left, right| right.modified_at_unix.cmp(&left.modified_at_unix));
103 +     pending.sort_by_key(|right| std::cmp::Reverse(right.modified_at_unix));
    |

error: consider using `sort_by_key`
   --> crates/kuzushi-core/src/runtime/application/loop_checkpoint.rs:120:5
    |
120 |     pending.sort_by(|left, right| right.modified_at_unix.cmp(&left.modified_at_unix));
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
    = help: for further information visit https://rust-lang.github.io/rust-clippy/rust-1.96.0/index.html#unnecessary_sort_by
help: try
    |
120 -     pending.sort_by(|left, right| right.modified_at_unix.cmp(&left.modified_at_unix));
120 +     pending.sort_by_key(|right| std::cmp::Reverse(right.modified_at_unix));
    |

error: could not compile `kuzushi-core` (lib) due to 5 previous errors
warning: build failed, waiting for other jobs to finish...
error: could not compile `kuzushi-core` (lib test) due to 5 previous errors

real	1m23.112s
user	2m11.893s
sys	0m12.018s
clippy_exit=101
```

</details>

## 5. Workspace test tail at a7cd9d9b (gates-rust-test.log)

Tail of `cargo test --workspace`: the kuzushi-bdd-tui onboarding failure that remained unclassified when the operator directed a pull instead of a rerun.

<details>
<summary>gates-rust-test.log</summary>

```text
=== GATE: cargo test --workspace ===
running 9 tests
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
error: test failed, to rerun pass `-p kuzushi-bdd-tui --test onboarding`

real	7m52.347s
user	14m47.600s
sys	2m49.641s
test_exit=101
```

</details>

## 6. Gate re-run at 63569495 (gates-rust-2-newhead.log)

fmt now clean; clippy blocked by the HTTPS dependency switch on a box without HTTPS credentials (worked around via an untracked user-level cargo patch); architecture gate still red; model-safety now green.

<details>
<summary>gates-rust-2-newhead.log</summary>

```text
BASELINE 63569495c451fbd08f34e6fd32661b68aea0d666
=== fmt ===
fmt_exit=0
=== clippy ===
error: failed to get `cpg-analysis` as a dependency of package `kuzushi-cpg v0.24.0-alpha.8 (/home/ci/kuzushi/crates/kuzushi-cpg)`
clippy_exit=101
=== arch ===
arch_exit=1
Kuzushi DDD boundary check failed:
- context builds repository facts without scanner runtime or tool execution: crates/kuzushi-core/src/modules/context/build_context_snapshot.rs
- context builds repository facts without scanner runtime or tool execution: crates/kuzushi-core/src/workspace/inventory/build_repository_inventory.rs
- report boundary reads artifacts and findings without execution: crates/kuzushi-core/src/report/confirmed_sarif.rs
- TUI renderers consume view models without stores or runtime dispatch: crates/kuzushi-tui/src/renderer/failure_coverage.rs
- TUI renderers consume view models without stores or runtime dispatch: crates/kuzushi-tui/src/renderer/phase_composition_contract/failure_snapshots.rs
- TUI renderers consume view models without stores or runtime dispatch: crates/kuzushi-tui/src/renderer/surface_lints.rs
- TUI presentation reads hydrated view data without synchronous artifact IO: crates/kuzushi-tui/src/renderer/failure_coverage.rs
- TUI presentation reads hydrated view data without synchronous artifact IO: crates/kuzushi-tui/src/renderer/phase_composition_contract/failure_snapshots.rs
- TUI presentation reads hydrated view data without synchronous artifact IO: crates/kuzushi-tui/src/renderer/surface_lints.rs
- TUI runtime wording avoids unproven validation claims: crates/kuzushi-tui/src/renderer/failure_coverage.rs
- TUI agent chat renderer reads agent chat view model: no production Rust files matched roots crates/kuzushi-tui/src/renderer/views/chat/agent_chat_lines
=== model-safety ===
Model safety check passed.
=== crap ===
crap_exit=0
=== node test ===
test_exit=0
```

</details>

## 7. Final baseline 06a3a2a0 (gates-newhead-rust.log)

clippy/test blocked by the kuzushi-mcp-common Linux compile break (KZ-3 / ETR-002).

<details>
<summary>gates-newhead-rust.log</summary>

```text
HEAD=63569495c451fbd08f34e6fd32661b68aea0d666
=== clippy ===
help: to reborrow the mutable reference, add `*`
    |
263 |     append_linux_authorized_root(&mut *command, &access.tool_root, true, &mut retained_handles)?;
    |                                       +
help: to reborrow the mutable reference, add `*`
    |
265 |         &mut *command,
    |              +
help: to reborrow the mutable reference, add `*`
    |
278 |     append_linux_authorized_root(&mut *command, &scratch, false, &mut retained_handles)?;
    |                                       +
help: to reborrow the mutable reference, add `*`
    |
274 |         append_linux_authorized_root(&mut *command, root, false, &mut retained_handles)?;
    |                                           +
help: to reborrow the mutable reference, add `*`
    |
271 |         append_linux_authorized_root(&mut *command, root, true, &mut retained_handles)?;
    |                                           +

Some errors have detailed explanations: E0596, E0599.
For more information about an error, try `rustc --explain E0596`.
error: could not compile `kuzushi-mcp-common` (lib) due to 3 previous errors
warning: build failed, waiting for other jobs to finish...

real	0m6.204s
user	0m17.664s
sys	0m4.688s
clippy_exit=101
=== cargo test ===
error[E0599]: no method named `path` found for reference `&std::path::Path` in the current scope
error[E0599]: no method named `path` found for reference `&std::path::Path` in the current scope
error[E0596]: cannot borrow `command` as mutable, as it is not declared as mutable
error: could not compile `kuzushi-mcp-common` (lib) due to 3 previous errors

real	0m9.186s
user	0m25.455s
sys	0m4.601s
test_exit=101
```

</details>
