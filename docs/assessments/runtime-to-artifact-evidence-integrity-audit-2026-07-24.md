# Runtime-to-Artifact Evidence Integrity Audit — 2026-07-24

Audit-only pass over Kuzushi's end-to-end execution truth: does the operator get
what they asked for, executed how they configured it, with live progress,
terminal outcomes, artifacts, findings, proof, and cost that agree everywhere?

## 1. Executive verdict: **FAIL**

The dispatch spine, typed lifecycle, no-silent-fallback policy, torn-tail
quarantine, and startup recovery are genuinely strong — several checks that
routinely fail in comparable systems pass here with distinction. But the audit
confirmed hard breaks in the invariants this repository names as
load-bearing:

1. A **model-only opinion persists and presents as empirical runtime proof**
   (`Confirmed` / "runtime_verified — empirical verification evidence
   recorded"), including in SARIF and every export (ETR-001).
2. **HEAD does not compile on Linux**, so no binary, no test, and no CI truth
   can even be established from the audited commit on this platform (ETR-002).
3. A **failed provider call becomes a successful run**: `triage:run` with a
   failing model call reports `completed`, "Triaged 1 of 1 findings",
   `failures: []`, exit 0 — live-proven three times (ETR-003).
4. `runs prune` **deleted a live, mid-write run** in a live experiment,
   destroying its evidence and converting a successful execution into a
   spurious failure (ETR-005).
5. A crash window at terminalization leaves `run.json` terminal with **no
   typed terminal item, permanently unrepairable** — already observed on 5 of
   72 real runs on this machine (ETR-006).

Because items 1–3 mean an operator can be told "verified/complete" when
neither is true, the verdict is FAIL, not PASS WITH GAPS.

## 2. Audited baseline and binary provenance

| Item | Value |
|---|---|
| Timestamp (UTC) | 2026-07-24T16:21:12Z (evidence gathered 16:21–18:00 UTC) |
| Repository | /home/ci/kuzushi |
| Branch | main |
| HEAD | `06a3a2a0f82079858f5b5a502bee0dce97f1e755` (== origin/main after fetch; no drift during audit) |
| Tree | clean of tracked changes (one untracked `.audit/` dir from a prior session; untouched) |
| Kuzushi version | 0.24.0-alpha.8 |
| rustc / cargo | 1.96.1 / 1.96.1 |
| node / pnpm | v22.22.2 on PATH (Node 26.5.0 available at ~/.local for KWP-gated tests) / 10.30.0 |
| OS | Linux 6.17.0-1008-gcp x86_64 |
| Provider readiness | `ANTHROPIC_VERTEX_PROJECT_ID` set; gcloud ADC present and able to mint tokens; `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` unset. No secret values displayed or persisted. |

**Binary provenance.** HEAD cannot produce a binary on Linux (ETR-002):
`kuzushi-mcp-common` fails to compile and `kuzushi-cli` depends on it via
`kuzushi-core → kuzushi-codeindex` (verified with `cargo tree -i`). Existing
binaries self-report `a7cd9d9b0+dirty` (debug) and `d632466ee+dirty` (release)
— neither is HEAD, and neither was used for HEAD evidence. All live tests used
binaries built from an isolated copy at `/tmp/kuzushi-etr-audit/src` checked
out at `06a3a2a0` **plus exactly one disclosed 3-line compile fix** confined to
`crates/kuzushi-mcp-common/src/read_only_sandbox/backend.rs` (`mut` binding at
:258; `scratch.path()` → `scratch` at :291/:294 — the mechanical resolution of
the three compile errors, no behavior redesign). Both binaries embed honest
provenance: `kuzushi 0.24.0-alpha.8 (06a3a2a0f+dirty · debug)` and
`(06a3a2a0f+dirty · release)`. The repository itself was never modified;
`Cargo.lock` perturbations from read-only cargo queries were restored to the
committed state and the tree re-verified clean before this report was written.

## 3. Scope and explicit exclusions

In scope: dispatch/input convergence (A), provider/runtime/model/auth truth
(B), typed lifecycle (C), durable artifact consistency (D), projection parity
(E), cancellation/cleanup (F), finding/proof/patch provenance (G), fault
matrix (H), test bar, live journeys in isolated HOME/XDG/run stores, one
approved live provider call.

Exclusions: general visual design (only truth-bearing presentation was
inspected); interactive-TTY-only journeys needing tmux (two-stage Ctrl+C was
audited in code, not keystroke-driven); Windows/macOS behavior; KWP dynamic
module live journeys (Node ≥25 gate — classified environmental, one
representative test re-run under Node 26 to prove the classification);
`fuzz:*` engine execution. Prior audit documents were used as hypotheses only;
every carried-over claim was re-verified at this HEAD with fresh line numbers.

## 4. End-to-end architecture and causality map

All three modes converge on one boundary in
`crates/kuzushi-core/src/modules/builtins/with_v2_builtins/execution.rs`:

- Preparation: `prepare_tool_input` (:199 — stored-option merge, descriptor
  option validation with unknown-key rejection, prompt-input limits) →
  `prepare_tool_input_for_dispatch` (:167 — workspace path normalization,
  declared prompt-file defaults, repository binding) → `prepare_dispatch_input`
  (:180 — mints a `PreparedDispatchBinding` fingerprint over registry identity,
  descriptor, input, and workspace).
- Dispatch: `dispatch_prepared_input_with_lifecycle` (:265) →
  `verified_dispatch_descriptor` (:308 — re-verifies the fingerprint so a
  prepared input cannot be replayed against a different registry/input/
  workspace) → `authorize_prepared_execution` (:525 — context, path/write
  authorization, **autonomy gate** `enforce_autonomy_posture` :537 which only
  refuses, approval gate, runtime requirement, findings-store requirement) →
  `invoke_prepared_executor` (:424 — trace scoping, `TracedRuntime` wrap,
  executor, `normalize_tool_output_contract`).

Mode entries (full file:line chains in §5): `kuzushi run` via
`kuzushi-cli/src/application/run_tool.rs` + `run_tool_prepare.rs`; shell tool
dispatch via `kuzushi-tui/src/app/tool_runner/run_tool/` + background worker
`run_background_tool.rs`; `kuzushi scan` via `application/scan_prepare.rs` /
`scan.rs` into `sast:scan`, whose engine and triage/verify/patch sub-stages
re-enter the same boundary via delegated dispatch.

Persistence: single hash-chained writer per run
(`run_lifecycle/persistence/writer*.rs`, exclusive `items.lock`, fsync per
batch, delivery pump re-reads the durable file and re-verifies the chain
before fan-out to `ShellEvent::RunItem`). Terminalization
(`run_artifacts/tool_run_record.rs`) writes result.json → `ToolCallFinished`
(with result digest) → run.json (atomic) → typed `TerminalOutcome`. Read-time
recovery (`run_summary_store.rs:803-975`) uses pid + boot-id/start-token
identity (`.process-identity.json`), not age.

## 5. Invariant matrix across scan, shell, and run

| Invariant | Verdict | Evidence |
|---|---|---|
| Three-mode convergence on prepare+dispatch | **PASS** | run: `run_tool_prepare.rs:344` → `execution.rs:180/256`; shell: `background.rs:288-307` → `run_background_tool.rs:65`; scan: `scan_prepare.rs:240` + `scan.rs:409-427`; sast sub-stages: `from_tasks.rs:335-365`, `optional_positive_count.rs:189-201`; patch:reverify re-dispatch: `reverify.rs:129` → `dispatch_delegated_tool_with_runtime` |
| Unknown option rejection at canonical boundary | **PASS** (live) | `options/json_summary.rs:60-86`, no passthrough/`_`-prefix escape; live: `recon:import` unknown key → `blocked`, exit 2, allowed keys listed |
| Unknown tool | **PASS** (live) | `blocked` + exit 2 + actionable next |
| Workspace tools require explicit target; no cwd substitution | **PASS** (live) | `tool_requirements.rs:91-94`; live: explicit error naming `--target` |
| Stored-option precedence identical across modes | **PASS** | one implementation, `options/option_store_effective_input.rs:149-252`; workspace-scope stored options blocked from prompt/model/path keys (`execution.rs:783-843`) |
| Prompt overrides via shared boundary only | **PASS** | `execution.rs:1294-1371`; sast forwarding `sast_scan/prompt_overrides.rs:3-59`; target prompt text wrapped in untrusted framing |
| Runtime requirements descriptor-driven, shared | **PASS** | `runtime_requirements.rs`; consumers verified identical in CLI/TUI/scan |
| Autonomy gate runs at dispatch, only refuses | **PASS** (live) | `execution.rs:537,652-681`; `autonomy/mod.rs:186-227` fails closed on unclassified; live: `patch:finding --autonomy recon` refused with actionable message |
| Target config cannot steer policy | **FAIL** | `[phases]` missing from `forbidden_project_fields` — ETR-011 |
| Mode-specific bypasses | PASS with notes | TUI `findings export`/scope-init/reindex and threat-model regen/ask workers bypass the boundary (shell-only, low risk — P3 register) |
| `--ci` scan-only, run emits JSON | PASS (live) | observed |

## 6. Provider / runtime / model evidence

Static (all re-verified at HEAD): no-silent-fallback holds. Enforcement in
`runtime/policy/no_silent_fallback.rs` (missing/empty model → hard error;
cross-provider credential refusal); zero hardcoded model fallbacks in non-test
code; `models.toml` fallback chains rejected at load
(`router_state.rs:133-143`); target-local model/models.toml rejected; env
discipline ratcheted by `env_boundary_lint.rs` (currently RED — see ETR-019);
retries are same-model transport-only (`transport_retry.rs:20-136`, bridge
429 windows ≤3, LangChain maxRetries 8 — model object reused everywhere);
provider errors keep class + HTTP status + bounded 300-char detail.

Live (approved spend, total < $0.01):

- **Missing model**: `triage:run` with findings and no model → hard error
  "requires an explicit model … Kuzushi will not choose a fallback model",
  exit 3, `failed` consistently persisted. PASS.
- **Real provider round trip (bridge layer)**: HEAD bridge script +
  `@anthropic-ai/vertex-sdk` + gcloud ADC completed a real
  `vertex-anthropic:claude-haiku-4-5` call (response "pong", 15 in / 5 out
  tokens, `model_calls: 1`) — **but `cost_reported_calls: 0`,
  `cost_usd_exact: false`**: the vertex path reports usage and never cost
  (ETR-017).
- **No region configured** → the vertex call **hangs indefinitely** (>120 s,
  zero output; no default bridge timeout — `KUZUSHI_BRIDGE_TIMEOUT_MS` is
  opt-in). ETR-017.
- **Full Rust-runtime → provider path**: NOT proven live. In the isolated
  config-less environment every kuzushi-level model call failed pre-bridge in
  5-6 ms with error class `authentication`; the root precondition is
  UNVERIFIED (cheapest falsification: repeat with an operator `config.toml`
  pinning runtime provider + `CLOUD_ML_REGION`). The attempt itself produced
  ETR-003: the failure was swallowed into a successful run, and **no durable
  artifact records the cause** (`failures: []`, empty triage sidecar, only the
  bare class in one diagnostic item). `auth ping` — the dedicated diagnostic —
  dead-ends at "raw error details were suppressed" (P3 register).
- Structured output: `forcedConclusion` after recursion exhaustion is
  indistinguishable from a natural conclusion (`langgraph-bridge.mjs:72-110`,
  `:225-259`), and the first structured-JSON parse is attempted before the
  `truncated` check (`structured_json_contract.rs:205-241`,
  `runtime_impl.rs:350-357`) — ETR-012. Verify/triage verdict parsing itself
  is strict (hard-fails on missing/mistyped fields, hallucinated fingerprints,
  non-majority consensus).

## 7. Lifecycle and artifact consistency evidence

Strong under honest conditions (live, isolated store): a successful
`context:build` produced a hash-chained `items.jsonl` (`seq` 1..15, exactly one
`terminal_outcome`), `run.json`/`result.json`/`done.json`/terminal item all
`completed`, artifact digests bound into the stream
(`ToolCallFinished.result_artifact` sha256, `run.json.terminalResultSha256`),
cost recorded as `completeness: "unavailable"` rather than a bare $0, and
`progress_truncated` items disclosing coalescing. Cost conflicts between
run.json and summed item costs are rejected (`lifecycle_cost.rs:16-38`).

Confirmed breaks:

- **Terminalization order** (`tool_run_record.rs:132→143`, `:266→277`,
  `:499→509`): run.json goes terminal before the typed terminal item; recovery
  triggers only on `status=="running"` (`run_summary_store.rs:816-818`) and its
  completeness check accepts file existence (`:846-856`) — the divergence is
  permanent. **Observed on real data**: 5 of 72 runs under two real target
  stores on this box have `run.json=interrupted` with no `terminal_outcome`
  in items.jsonl. ETR-006.
- **Recovery overwrites a durably-written real result.json** with a synthetic
  interruption stub (`run_summary_store.rs:906-931`) — evidence destruction in
  the T2→T4 crash windows; the hash-chained result digest then contradicts
  disk. ETR-006.
- **Writer-side torn tail bricks the run**: `recover_tail` hard-fails
  (`writer_open.rs:47-49`), recovery cannot reopen a writer, and every
  subsequent `load_run_summary` errors — permanent `UnreadableMetadata`.
  events.jsonl and the scan sidecars fuse records after a torn tail
  (`jsonl_append.rs:7-14`) — the findings event log heals exactly this
  (`event_log/mod.rs:227`); the run stores do not. ETR-008.
- **Reader-side torn tail** (terminal already durable) is handled with
  distinction — live: appended garbage to a completed run's items.jsonl →
  shell replay, CLI trace, and release-binary `runs trace` all **quarantined**
  the completed claim: "recorded completed status quarantined: stream
  integrity is degraded", downgrading Completed→Partial with disclosure.
- **Stage checkpoints**: key embeds the process-local `NEXT_REGISTRY_IDENTITY`
  counter (`module_registry.rs:15,29`; `execution.rs:391-398`) so cross-process
  resume silently may not happen; dirty/non-git trees make any checkpoint
  "fresh" (`stage_checkpoint.rs:273-302`); write is unfsynced through a fixed
  `.json.tmp`; `PendingStageCheckpoint` disclosures have zero consumers.
  ETR-014.
- Findings receipts (`finding_delta`, run.json findings count) are derived
  from in-memory scan output and never reconciled against the findings store
  (P3 register).
- Crash/kill live journeys: SIGKILL and SIGINT mid-run both leave
  `run.json=running`; the next read repaired both to `interrupted` durably
  (typed terminal appended, pid+boot-identity verified) — recovery PASS, but
  the SIGINT case loses cancellation identity (ETR-009) because headless
  `kuzushi run` has no signal handler (the campaign dispatcher is the only
  `ctrl_c` handler in the repo).

## 8. Projection-parity evidence

Shared-truth architecture is real: shell replay/trace, CLI
`runs trace/replay`, plain mode, and Run Focus all consume the same durable
items stream; plain output serializes the same view models (parity sweep with
`KNOWN_SILENT = []`). Live checks: scripted plain shell, `runs list/show/trace`
(HEAD release binary), and durable artifacts agreed for completed, blocked,
skipped, and quarantined runs; `runs list --status` vocabulary matches the
persisted vocabulary.

Confirmed parity breaks:

- **`kuzushi run` stdout vs durable truth** (live): an autonomy-refused run
  printed `"status": "failed" / "patch:finding failed"` (exit 3) while
  run.json, result.json, and the terminal item all say `blocked`. done.json
  said `"status": "completed"` (exit 2) for prepare-blocked runs and labels
  runtime-blocked runs `failed` (`run_exit.rs:57-72`) — one run, three
  spellings across three machine-readable surfaces. ETR-010.
- **Unknown terminal statuses forge success**: an Ok envelope spelling
  `status:"canceled"` (or anything non-canonical) without top-level `ok:false`
  classifies Completed (`module_result.rs:128-147`), normalizes result.json to
  `completed` (`:246-283`), persists run.json `completed`
  (`tool_run_record.rs:854-865`), and exits 0. Reachable from dynamic/KWP
  modules. ETR-007.
- **Journey counts over a ≤500-row slice** (`refresh_findings.rs:25,49,126`;
  `with_limit.rs:7 MAX_LIMIT=500`; `journey.rs:353-464`): >500 findings pin
  Review forever with phantom "record dispositions for N of M" work, or — when
  the counts cache is absent — the slice-only fallback reads review COMPLETE at
  500/600. The NEXT-strip comment claims the counts come from the durable
  ledger; the code contradicts it. ETR-013.
- Scan-page attempt cost sums exact + observed + missing into a plain "$X"
  (`attempt.rs:161-167`) while `runs show` marks the same spend unresolved;
  CLI `runs list` prints unverifiable `running` rows with no qualifier where
  Jobs renders `Stale`/"running?"; `runs trace/replay` never trigger the
  stale-repair, so trace and show can disagree until a repairing read happens;
  interrupted phase attempts render "failed" in phase cards (all P2/P3
  register).
- `apply_committed_run_item` lacks the run-id guard its four sibling handlers
  have (`runtime_event_drains.rs:444-454` vs `:456-534`), so late items from a
  previous run can populate a fresh Run Focus session; the fallback session id
  (`manual-<ts>`, `:2311-2319`) then makes the guarded events drop as stale.
  ETR-016.

## 9. Cancellation and recovery evidence

Architecture: two-stage Ctrl+C with full-stop semantics (abort flags + token
cancel + planning-queue pause + steer-queue drain with receipt); scoped
`jobs -k` cancels exactly one slot; cancellation tokens SIGKILL registered
child process **groups**; scanners carry a SIGKILL-proof parent-death guard;
watchdog escalation persists `interrupted`; budget halt persists `canceled`
after explicit operator abort; read-time reconciliation converts dead-pid
`running` to `interrupted` under the terminal lock (live-proven twice).

Confirmed breaks (ETR-009 cluster):

- Planner/threat workers snapshot the cancellation disposition **before**
  execution (`planner_job.rs:30-32`, `threat_regen_worker/job.rs:31-33`), so a
  mid-flight cancel persists `failed`.
- Canceled `agent:ask` hardcodes the typed terminal `Failed`
  (`tool_run_status.rs:256-283`) while run.json records `canceled`; the typed
  stream cannot be corrected (terminal already exists) — Jobs says Canceled,
  replay says Failed, for the same run.
- Headless `kuzushi run` has no SIGINT handling (live: exit 130, run left
  `running`, later repaired to `interrupted`) — operator cancellation identity
  is lost, contradicting "operator cancellation persists as canceled".
- Scoped cancel leaves queued steer items armed; the next terminal event
  dispatches them silently (`effects.rs:897-920` vs `exit_requests.rs:42-49`).
- Completed-after-cancel is retained and disclosed (correct direction);
  failure racing a cancel resolves to `canceled` with the error in the reason
  (disclosed, acceptable).
- Survivors: bridge/KWP node groups have no parent-death lifeline (linger
  after SIGKILL of kuzushi until their pipes die); the detached campaign
  dispatcher is the only intentional survivor (verified only such spawn).
- **Campaign queue** (ETR-015): `recover_stale_running_jobs` flips every
  `running` row to `planned` on any open (`queue.rs:240-250`) with no
  liveness check; `save()` uses a fixed shared `queue.json.tmp` (`:205-213`);
  no dispatcher lock — a second dispatcher duplicates live jobs and the two
  corrupt each other's queue state.
- **`runs prune` vs live runs** (ETR-005, live-proven): plan filters only by
  age/keep-set (`runs_prune.rs:42-59`), deletion takes no locks (`:80-99`).
  In a live experiment the prune deleted the actively-running run's directory;
  the victim's terminalization then failed ("typed lifecycle is missing"),
  exit 3, leaving a skeleton dir of `done.json` + `.terminal.lock`. A
  successful execution was destroyed and misreported as a failure. (Session
  prune already knows this pattern — `skipped_live`.)

## 10. Finding / proof / patch provenance evidence

Strong: durable identity is line-free (survives line drift); same-run dedup
merges; proof attaches by identity with `verification_run_id` kept separate
from discovery `scan_id`; replay replays the verification run only; the
"proof belongs to a prior observation · revalidate" warning fires; import
paths write no proof; malformed verify output hard-fails rather than
defaulting; patch application records diff-hash/base-commit/touched-file
before-after hashes; `patch:reverify` strips caller-supplied detector keys and
rebinds from provenance, refuses after touched-file hash changes, and pins
finding generation; suppression exports carry explicit flags and SARIF
`suppressions[]`.

Confirmed breaks:

- **ETR-001** (the headline): `verify:finding` defaults to `mode="model"`; the
  tool's own response honestly says `empirical: false` — but selecting the
  Prove attempt persists `PersistedVerification { proof_verdict: Exploited,
  backend: Model, proof_level: model-claimed 1..=4 }`
  (`model_candidate.rs:44-93`, `selected_proof.rs:65-74`), and every
  classification surface is backend-blind: `proof_ladder.rs:79-85` →
  `Confirmed` + "verified — empirical runtime evidence recorded"
  (`proof_ladder_labels.rs:29-36`); lifecycle `runtime_verified`
  (`proof_state_label.rs:178-188`); exports/SARIF/markdown/PR comment carry
  `proof_confidence: confirmed` (`export_projection.rs:146`,
  `export_sarif.rs:188-236`). Only a small "L{n} · model" chip and the export
  `backend` field leak the truth. The ladder's own doc comment asserts the
  invariant the code violates.
- **ETR-018**: reverify's "deterministic" is proxied by
  `!tool_needs_runtime` (`reverify.rs:127`) — a runtime-requirement predicate,
  not the determinism whitelist the rescan reconciler uses. A runtime-free but
  nondeterministic detector (e.g. fuzz) that merely fails to re-find the crash
  classifies `Verified` and promotes `PatchStatus::Verified` where the honest
  outcome is `NotRediscovered`.
- P3 register: file rename mints a new identity and orphans proof (no
  rename-group machinery, `finding_identity.rs:71-80`); line-1 default /
  prose re-anchoring with no provenance marker across carlini
  (`normalize_findings.rs:103,111-133`), agentic_sast, uaf_hunt, taint_iris;
  offense chains hardcode `proof_level: 4` with any backend including Plain
  (`offense/persistence.rs:124`, no trust-plain clamp analog); detector
  identity is name-bound, not version/digest-bound; evidence-less findings
  with templated titles can share one identity across distinct instances.

## 11. Findings ordered by severity

Severity legend: P0 = false security confirmation / platform truth broken;
P1 = corruption, forged outcome, destroyed evidence; P2 = integrity drift an
operator can hit in normal use; P3 = register (listed in §14 ledger).
Confidence is High unless noted. "HEAD" = present on committed HEAD
06a3a2a0; nothing here is dirty-tree-only.

### ETR-001 (P0, HEAD, CONFIRMED — static x2 independent + prior live TUI pipeline)
**Model-backend "Exploited" presents as empirical runtime proof everywhere.**
Invariant: proof states are honest; `Confirmed` means runtime-exploited.
Consequence: a hallucinated model verdict exports to SARIF as
confirmed/runtime-verified. Paths: `crates/kuzushi-core/src/verification/application/selected_proof/model_candidate.rs:44-93`;
`selected_proof.rs:17-74`; `findings/presentation/detail/proof_ladder.rs:79-85`;
`proof_ladder_labels.rs:29-36`; `proof_state_label.rs:178-223`;
`workspace/application/export_projection.rs:146,339-349`;
`export_sarif.rs:188-236`. Repro: default `verify:finding` returning
exploitable/proofLevel 3 → select Prove attempt → finding detail / SARIF.
Existing coverage: renderer snapshots bake the "RUNTIME VERIFIED" wording in
as canonical (`phase_review_80x24.snap`), so tests enforce the defect.
Remediation direction: backend gate in `runtime_verified_ladder_kind` +
`verification_lifecycle_label` and a distinct "model-assessed (unverified at
runtime)" rung capped below Confirmed; cap `ModelProofCandidate::validate` at
the model-review proof tier. Regression: model-backend Exploited must never
render/export the runtime-verified label or Confirmed.

### ETR-002 (P0, HEAD, CONFIRMED live)
**HEAD does not compile on Linux; the whole workspace (binary, tests, gates)
is dead on the primary CI platform.**
`crates/kuzushi-mcp-common/src/read_only_sandbox/backend.rs:258` (E0596 via
call sites :263/:265/:271/:274/:278) and `:291,:294` (E0599), inside
`#[cfg(target_os = "linux")]`, introduced by the CodeQL/MCP hardening commit
2afc6624. `kuzushi-cli` depends transitively. Consequence: no HEAD binary, no
`cargo test` truth, merge train demonstrably not gated on a Linux build.
Remediation: the 3-line fix (validated in the audit copy: full workspace
`cargo check --all-targets` passes in 119 s afterward) plus a required Linux
`cargo check --workspace` merge gate. Regression: CI job on ubuntu.

### ETR-003 (P1, HEAD, CONFIRMED live ×3)
**`triage:run` converts provider/model-call failure into success.**
With one candidate finding and a failing model call (class `authentication`),
the run reports `completed`, "[+] Triaged 1 of 1 findings", `failures: []`,
exit 0; the finding is silently left `needs_review`; the cause survives only
as a bare class string in one diagnostic item — not in failures.json, not in
the sidecar, not in the exit code. Path: triage per-finding error swallowed by
the batch loop before `verdict-write` (see `triage:triage · triage failed
(authentication)` diagnostic followed by `verdict-write` in the same stream).
Violated: "missing credentials must not produce a misleading terminal state";
success/partial distinction. Expected: `partial`/`failed` with the
authentication cause in failures.json and nonzero exit when all (or any)
model calls fail. Regression: triage run with a stub runtime that errors →
assert non-success status + persisted cause. Note: agent:ask and single-call
paths do fail loudly; this is the batch path.

### ETR-004 (P1, HEAD, CONFIRMED live)
**Every `kuzushi runs` subcommand (list/show/trace/replay/diff/prune) panics
in any debug build; in release the duplicate option is silently tolerated.**
clap debug assertion: `--target` defined by both the global
(`cli/mod.rs:12-13`) and each subcommand (`command/subcommands.rs:172-173,
185-186, 195-196, 205-206, 217-218`, prune equivalent). Present since at least
a7cd9d9b. Consequence: the headless inspection surface is unusable under
`cargo run`/`pnpm dev`, and the panic proves zero test coverage over the runs
CLI parser (any debug-built test would trip it). Remediation: rename or scope
the subcommand-local arg (or drop it for the global); add a
`Cli::command().debug_assert()` test. |

### ETR-005 (P1, HEAD, CONFIRMED live)
**`runs prune` deletes live runs mid-write.**
`crates/kuzushi-cli/src/application/runs_prune.rs:42-59` (no running/liveness
filter), `:80-99` (`remove_dir_all`, no locks). Live: prune listed and deleted
the in-flight run; the victim later failed terminalization ("typed lifecycle
is missing for run …", exit 3) and left a skeleton dir — evidence destroyed,
successful work misreported as failure. Remediation: skip runs whose
`.process-identity.json` verifies live (reuse `process_identity.rs`), or take
the run terminal lock; report `skipped_live` like session prune. Regression:
prune with a live pid-verified running run must skip it.

### ETR-006 (P1, HEAD, CONFIRMED static + observed on 5/72 real runs)
**Terminalization crash window is permanently unrepairable, and recovery
destroys real results.**
Order run.json-before-typed-terminal at `tool_run_record.rs:132→143`,
`:266→277`, `:499→509`; recovery gate `run_summary_store.rs:816-818`;
existence-only completeness check `:846-856`; result.json overwrite
`:906-931`. Consequence: run.json says completed/interrupted while the
authoritative stream never terminates — replay/trace/Run Focus hydration and
`runs list` permanently disagree; a durably-written real result.json can be
replaced by a synthetic stub whose digest contradicts the hash chain.
Remediation: emit the typed terminal first (recovery already does, `:922→929`);
add a completed-but-unterminated reconciler; never overwrite an existing
result.json. Regression: kill between the two writes (fault hook) → next read
repairs; result.json preserved.

### ETR-007 (P1, HEAD, CONFIRMED static)
**Non-canonical terminal statuses coerce to `completed` + exit 0.**
`module_result.rs:128-147` (unknown → Completed), `:246-283` (normalization
erases the spelling into `data.status`), `tool_run_record.rs:854-865`,
`run_exit.rs:57-63`. A dynamic/KWP module returning `{"status":"canceled"}`
without `ok:false` forges success across stdout, result.json, run.json,
items.jsonl, and the exit code — consistent, but consistently wrong.
Remediation: fail closed (or preserve) unknown statuses at
`canonical_tool_result_status`. Regression: envelope with `status:"canceled"`
and no `ok` must not classify Completed.

### ETR-008 (P1, HEAD, CONFIRMED static; reader-side quarantine PASS live)
**Writer-side torn items.jsonl tail bricks a run forever; events/sidecar
appends fuse records after torn tails.**
`writer_open.rs:47-49` (fail-closed reopen), `run_summary_store.rs:166-170`
(every read errors thereafter; permanent `UnreadableMetadata`, `:479-482`);
`jsonl_append.rs:7-14` (no healing; contrast `event_log/mod.rs:227`).
Remediation: valid-prefix truncation/quarantine for the writer reopen path,
`heal_torn_tail` for run-events/sidecars. Regression: torn final line + dead
owner → run recovers to interrupted.

### ETR-009 (P2, HEAD; parts live)
**Cancellation identity loss cluster.** (a) planner/threat cancel persists
`failed` (`planner_job.rs:30-32`, `threat_regen_worker/job.rs:31-33,69-71` —
disposition snapshotted before execution); (b) canceled `agent:ask` writes
typed terminal `Failed` while run.json says `canceled`
(`tool_run_status.rs:256-283` vs `agent_events.rs:71-83`) — surfaces disagree;
(c) headless SIGINT (live) → eternal `running` repaired later to
`interrupted`, never `canceled`; (d) scoped `jobs -k` leaves steer items armed
→ surprise dispatch after cancel (`effects.rs:897-920`). Remediation: read
disposition after execution (pattern exists in
`parse_threat_patch_json.rs:229-263`); consult disposition in the loop
terminal; add a SIGINT handler to headless run persisting `canceled`; drain or
disclose steer items on scoped cancel.

### ETR-010 (P2, HEAD, live)
**One run, three statuses: stdout vs run.json vs done.json.** Autonomy-refused
run: stdout `failed`/exit 3, durable `blocked`; prepare-blocked runs: done.json
`"status":"completed"` with exitCode 2 (live), runtime-blocked: done.json
`failed` (`run_exit.rs:57-98`). The stdout JSON is the raw executor envelope,
not the normalized result.json (`run_tool.rs:299-388` vs
`tool_run_record.rs:154-183`) — two serializations drift. Remediation: emit
the normalized result on stdout; make done.json carry the run status
vocabulary (or rename its field to reflect sentinel semantics); align exit
codes with `blocked`.

### ETR-011 (P2, HEAD)
**Untrusted target `[phases]` clamps operator autonomy and the walker.**
`load_config_for_target.rs:327-415` (missing from forbidden fields; merged
unconditionally), `run_tool_prepare.rs:116-129` (explicit `--autonomy`
clamped), TUI live-reload `navigation_target_story.rs:178-229`, walker stop
`onboarding_open.rs:255-273`. Fail-closed direction (can only lower), one
stderr notice — but a scanned repo silently degrading its own scan depth is an
evidence-integrity breach of the stated trust contract. Remediation: add
`phases` to `forbidden_project_fields` (operator config/env only).

### ETR-012 (P2, HEAD)
**Structured-output honesty gaps in the bridge.** (a) `forcedConclusion`
(recursion exhaustion) returns `ok:true, truncated:false`, byte-shape
identical to a natural verdict (`scripts/langgraph-bridge.mjs:72-110,
225-259`; contrast MCP-timeout marking, `model.mjs:392-400`); (b) first-pass
structured-JSON acceptance skips the `truncated` refusal
(`structured_json_contract.rs:205-241`; `runtime_impl.rs:350-357`).
Remediation: `stopReason:"forced_conclusion"`/`truncated:true`; move the
truncation check before the first parse.

### ETR-013 (P2, HEAD)
**Journey/NEXT counts computed over a ≤500-row slice.**
`refresh_findings.rs:25,49,126` + `with_limit.rs:7` + `journey.rs:353-464,
571-598`. >500 findings: Review pins forever with phantom work; cache-absent
fallback forges review-complete at exactly 500. Contradicts "counts come from
the unfiltered ledger". Remediation: compute `reviewed/confirmed/proven` via
store aggregate queries, not the display slice.

### ETR-014 (P2, HEAD)
**Stage-checkpoint resume is unreliable and undisclosed.** Process-local
registry-identity in the operation fingerprint (`module_registry.rs:15,29`;
`execution.rs:391-398`); dirty/non-git trees treat any checkpoint as fresh
(`stage_checkpoint.rs:273-302`); unfsynced fixed `.json.tmp` (`:90-96`);
`PendingStageCheckpoint` disclosures unconsumed. failures.json promises
automatic resume that silently may not happen. Remediation: stable identity
input (registry fingerprint already exists), disclose or refuse dirty-tree
reuse, unique temp + fsync.

### ETR-015 (P2, HEAD)
**Campaign queue: pid-blind recovery, no dispatcher lock, shared temp file.**
`campaign_run/queue.rs:205-213, 240-250`; `campaign_run/mod.rs:191-235`.
Second dispatcher re-marks live jobs `planned` (duplicate dispatch) and the
fixed `queue.json.tmp` races corrupt state. Remediation: dispatcher lockfile +
process-identity-verified recovery (machinery exists for runs).

### ETR-016 (P2, HEAD)
**Run Focus can display a different run's items.** `apply_committed_run_item`
lacks the run-id guard of its four siblings
(`runtime_event_drains.rs:444-454` vs `:456-534`); fallback session minted
with `manual-<ts>` id (`:2311-2319`) then drops the real run's guarded events
as stale. Remediation: same guard as siblings; mint fallback session with the
event's run id.

### ETR-017 (P2, HEAD; live)
**Vertex cost truth and timeout.** Live: bridge reports token usage but no
cost (`cost_reported_calls: 0`); Rust then shows "observed cost … =$0.0000
(provider spend unresolved)" — flagged, but a zero-valued lower bound with
known token usage reads as free; `PersistedVerification.cost_usd` writes bare
`0.0` when unavailable (`model_candidate.rs:113-115`); Scan-page attempt sums
mixed cost as exact (`attempt.rs:161-167`). No default bridge wall-clock: a
missing `CLOUD_ML_REGION` hangs a vertex call indefinitely (live >120 s).
Remediation: price known usage or display "usage 20 tok · cost unresolved"
instead of $0.0000; default `KUZUSHI_BRIDGE_TIMEOUT_MS`; `>=$X incomplete`
on the Scan aggregate.

### ETR-018 (P2, HEAD)
**Reverify determinism proxy can mint `Verified` from nondeterministic
absence.** `reverify.rs:127` (`!tool_needs_runtime`) vs the deterministic
whitelist (`rescan_reconciliation.rs:39-48`); promotion at
`reverify/support.rs:129-147`. Remediation: descriptor-declared determinism
bit or the shared whitelist.

### ETR-019 (P2, HEAD, live test bar)
**Main is test-red beyond the compile break** (with the compile fix applied,
isolated copy, exact numbers §13): `env_boundary_lint` fails — unaudited
`std::env` read added in `codeql_repository_execution/launcher.rs`;
`systems_hunt` standalone stages report `Null` provider cost where tests
require exact `0.01` (deterministic, reproduced in 1.4 s under Node 26 — a
real cost-attribution regression); `builtin_dispatch_policy_inventory` gate
red (policy tuples changed without fingerprint review); two TUI codeql tests
fail on the new database source-provenance check against their own fixtures.

## 12. Fault-injection results

| Fault | Result |
|---|---|
| Unknown tool | PASS — blocked, exit 2, actionable |
| Unknown option | PASS — blocked at canonical boundary, allowed keys listed |
| Missing target | PASS — explicit, no cwd substitution |
| Missing model (work present) | PASS — hard error, no fallback, exit 3 |
| Missing credentials (batch triage) | **FAIL** — ETR-003 (completed/exit 0) |
| Autonomy refusal | PASS gate / **FAIL** stdout status (ETR-010) |
| Duplicate `--run-id` | PASS — refused with path |
| SIGKILL mid-run | PASS — eternal running repaired durably to interrupted on next read (pid+boot identity) |
| SIGINT mid-run (headless) | **PARTIAL** — repaired to interrupted, canceled identity lost (ETR-009c) |
| Torn items.jsonl tail after terminal | PASS with distinction — quarantined with disclosure on every surface (shell replay, CLI trace, release binary) |
| Torn tail before terminal (writer reopen) | **FAIL** (static) — ETR-008 |
| Prune during live run | **FAIL** (live) — ETR-005 |
| Provider timeout / missing region | **FAIL** — indefinite hang, no default bridge timeout (ETR-017) |
| Provider 429/5xx | PASS (static) — same-model bounded retries, class+status preserved; not live-injected |
| Truncated/malformed structured output | PARTIAL — verdict parsing strict; first-parse truncation bypass + unmarked forcedConclusion (ETR-012) |
| Duplicate lifecycle event | PASS (static) — bit-identical accepted, divergent rejected; post-terminal new work accepted (P3) |
| Unknown terminal status from module | **FAIL** (static) — ETR-007 |
| Stale running run at startup | PASS — live-proven repair; unverifiable rows: Jobs discloses, CLI does not (P3) |

## 13. Test and live-journey evidence

All in the isolated copy (`06a3a2a0` + 3-line compile fix),
`CARGO_TARGET_DIR=/tmp/kuzushi-etr-audit/target`, commit for every row =
06a3a2a0+fix. Exit codes captured directly (no pipelines).

| Command | Exit | Duration | Result |
|---|---|---|---|
| `cargo check -p kuzushi-mcp-common` (repo, unfixed HEAD) | fail | — | 3 compile errors — ETR-002 |
| `cargo check --workspace --all-targets` (fixed copy) | 0 | 119 s | PASS |
| `cargo test -p kuzushi-core` | 101 | 351 s | 3958 passed / **35 failed** / 4 ignored — ~29 environmental (KWP needs Node ≥25; representative test re-run PASSED under Node 26.5.0), real: env_boundary_lint, 2× systems_hunt exact-provider-cost (re-verified deterministic under Node 26, 1.4 s), dispatch-policy inventory, codeql symlink test (env-probable, UNVERIFIED) |
| `cargo test -p kuzushi-cli` | 101 | 41 s | 217 passed / 1 failed (Node-version environmental, same KWP gate) |
| `cargo test -p kuzushi-tui` | 101 | 349 s | 2390 passed / 4 failed — 2× codeql fixture provenance (real, ETR-019), input-to-paint p95 (loaded-box perf, environmental), truecolor snapshot (UNVERIFIED — rerun on idle box is the falsification) |
| `cargo test --workspace` | 101 | 336 s | union of the above |
| Debug + release binary builds from HEAD+fix | 0 | 178 s / ~9 min | provenance strings `06a3a2a0f+dirty` |

Live journeys (isolated HOME/XDG/targets under /tmp/kuzushi-etr-audit):
J1-J3 unknown tool/option/target; J4 deterministic success + full artifact
agreement; J5 runs list/show/trace parity (HEAD release binary); J6 SIGKILL;
J7 torn tail + quarantine; J8 SIGINT; J9/J13 missing-model; J10 autonomy;
J11 run-id reuse; J12 offline demo (honest `signal_only`); J14 `kuzushi scan`
(1 finding, skipped engines disclosed); J15 scripted plain shell; J16 `ci`
gate; prune-live-run; live bridge round trip (pong, 15/5 tokens); live
kuzushi-level triage ×3 (ETR-003). Planted-secret check: the demo/scan
transcript stores did not leak the planted AKIA string in these journeys
(pattern-based transcript redaction gaps remain a static concern — P3).

## 14. Closure ledger

States: **identified** (this audit) → implemented → tested → verified-live →
merged → released. Everything below is **identified only** at
06a3a2a0f82079858f5b5a502bee0dce97f1e755; nothing is implemented, merged, or
released. "Live" column = live verification required before closure.

| ID | Repro evidence | Subsystem | Fix boundary | Regression test | Live check | Release-blocking |
|---|---|---|---|---|---|---|
| ETR-001 | static x2 + prior TUI pipeline | findings presentation + verification application | proof_ladder / proof_state_label / model_candidate | model-backend never renders runtime-verified/Confirmed | export SARIF after model verify | **Yes** |
| ETR-002 | live compile fail; fix validated in copy | kuzushi-mcp-common sandbox | backend.rs 3 lines + Linux CI gate | ubuntu cargo check job | CI green | **Yes** |
| ETR-003 | live ×3, artifacts on disk | triage batch loop | per-finding error propagation → partial/failed + failures.json | stub runtime error → non-success | rerun with bad creds | **Yes** |
| ETR-004 | live panic (2 binaries) | kuzushi-cli clap defs | subcommands.rs target args | `Cli::command().debug_assert()` | debug `runs list` | **Yes** |
| ETR-005 | live deletion + skeleton dir | runs retention | liveness/lock in runs_prune | prune skips live run | repeat experiment | **Yes** |
| ETR-006 | static + 5/72 real runs | run_artifacts terminalization/recovery | emit typed terminal first; reconciler; preserve result.json | kill-between-writes fault hook | crash-window harness | **Yes** |
| ETR-007 | static, repro sketch via dynamic module | module_result normalization | fail-closed unknown statuses | canceled-spelling envelope ≠ Completed | KWP module returning canceled | **Yes** |
| ETR-008 | static (writer path) | run_lifecycle writer / jsonl_append | tail quarantine + heal_torn_tail | torn tail + dead owner recovers | power-loss sim | Yes |
| ETR-009 | live (c) + static (a,b,d) | TUI workers + CLI signals | disposition-after-execution; SIGINT handler | cancel-mid-flight persists canceled | Ctrl+C journeys | Yes |
| ETR-010 | live (three spellings) | run_tool stdout/done.json/run_exit | one normalized serialization | stdout==result.json status | blocked-run journey | Yes |
| ETR-011 | static, config repro 2-liner | config load | forbid project `[phases]` | project phases rejected | clamp repro | Yes |
| ETR-012 | static | bridge + structured_output | stopReason marker; truncation-first | forced conclusion marked | recursion-limit run | Yes |
| ETR-013 | static | TUI journey counts | store aggregate counts | 600-finding journey truthful | seed 501+ findings | Yes |
| ETR-014 | static | run_artifacts stage_checkpoint | stable key, disclosure, fsync | cross-process resume works | staged-tool resume | No |
| ETR-015 | static | campaign_run queue | lock + identity recovery | double-dispatcher test | two dispatchers | No |
| ETR-016 | static | TUI runtime_event_drains | run-id guard | stale item ignored | background switch journey | No |
| ETR-017 | live (usage-no-cost; hang) | bridge cost/timeout + cost display | default timeout; price-or-disclose | vertex usage → non-$0 display | re-ping vertex | No |
| ETR-018 | static | patch reverify | determinism source | fuzz-origin reverify ≠ Verified | fuzz patch journey | No |
| ETR-019 | live test runs | multiple (lint/cost/policy/fixtures) | per-failure | the failing tests themselves | CI green | Yes (as CI gate) |

P3 register (identified; not release-blocking): rename orphans proof;
line-1/prose re-anchoring markers (4 capabilities); offense `proof_level: 4`
with any backend; detector name-vs-digest binding; evidence-less identity
over-collapse; CLI `runs list` confident `running` for unverifiable rows;
trace/replay repair-order divergence; interrupted-as-failed phase cards;
post-terminal item acceptance; duplicate Blocked re-apply; `next fresh`
unreachable (`shell_command_specs/mod.rs:146` shadows `single_arg.rs:77-83`);
`--option` typo silently dropped; TUI export/scope/reindex and threat-regen
boundary bypasses; `interactive_request()` caller-assertable; bridge/KWP no
parent-death lifeline; silent temperature drop for locked models
(`model.mjs:236-265`); `auth ping` dead-ends on suppressed detail; transcript
redaction is regex-only (AKIA/PEM/service-account JSON survive in turn text);
findings receipts unreconciled vs store; `$-0.00` trend formatting; exit-code
3 doc drift for blocked.

## 15. Residual risks and blocked verification

- **Full Rust-runtime → provider live path**: BLOCKED/partial. Proven at the
  bridge layer (real vertex call, HEAD script); the kuzushi-level call failed
  pre-bridge in the isolated environment with an unrecovered cause (itself
  ETR-003 evidence). Root precondition UNVERIFIED — falsify with an operator
  config.toml + region in a scratch HOME.
- Provider 429/5xx/timeout behavior verified statically only (no fault proxy
  injected against the real provider).
- Interactive two-stage Ctrl+C, steer/plan/chain ordering under cancel, and
  Run Focus geometry were audited in code, not keystroke-driven.
- KWP/dynamic-module live journeys blocked by the Node ≥25 gate on PATH
  (classification proven, behavior not exercised); ETR-007's dynamic-module
  repro is a sketch, not a live run.
- TUI truecolor snapshot failure and the codeql symlink unit test remain
  UNVERIFIED (idle-box rerun / codeql-present rerun are the falsifications).
- 5/72 real-run terminal divergences may have been written by older binaries
  on this shared box; HEAD's inability to repair them is confirmed either way.

## 16. Prioritized remediation sequence

1. **ETR-002** — 3-line compile fix + ubuntu `cargo check --workspace` merge
   gate (everything else is unverifiable until main builds).
2. **ETR-001** — backend-gate the proof ladder/labels/exports; add the
   model-assessed rung. (Highest trust impact.)
3. **ETR-003** — propagate per-finding model failures in triage to
   partial/failed + failures.json + exit code.
4. **ETR-004 + ETR-005** — fix the clap duplicate (unblocks debug dogfooding
   of `runs`), then liveness-guard prune.
5. **ETR-006 + ETR-008** — terminal write order, completed-but-unterminated
   reconciler, result.json preservation, torn-tail healing.
6. **ETR-007 + ETR-010** — one status vocabulary, fail-closed unknown
   statuses, normalized stdout/done.json.
7. **ETR-009** — cancellation disposition fixes + headless SIGINT.
8. **ETR-011, ETR-012, ETR-013** — trust boundary, structured-output honesty,
   ledger-true counts.
9. ETR-014..ETR-019, then the P3 register.

## 17. Cheapest next validation experiment

Fix ETR-002 (3 lines) on a branch, then run exactly:
`cargo test -p kuzushi-core --lib -- env_boundary_lint systems_hunt` under
Node 26 with `kuzushi run` built, plus `kuzushi --target <tmp> runs list` in a
debug build. Twenty minutes, and it simultaneously validates the compile fix,
re-confirms the two real cost/lint regressions of ETR-019, and reproduces
ETR-004 — the three cheapest-to-close findings in one pass.

---

### Final answers

- **Overall verdict:** FAIL.
- **Three highest-risk findings:** ETR-001 (model opinion presents and exports
  as empirical runtime proof), ETR-002 (HEAD unbuildable on Linux — no binary,
  tests, or CI truth), ETR-003 (failed provider calls become successful runs
  with the cause unrecorded).
- **Real provider execution proven?** Partially: a real vertex-anthropic call
  was completed through the HEAD bridge (token-accounted, cost-unreported);
  the full Rust-runtime path was not live-proven and is recorded as blocked.
- **Do all three modes converge?** Yes — scan, shell, and run all cross
  `prepare_dispatch_input` + `dispatch_prepared_input_*` with shared
  validation, autonomy, trace, and normalization; the bypasses found are
  shell-only presentation surfaces and two TUI workers (registered P3).
- **Do live and durable state agree?** On honest paths, yes (proven for
  success, blocked, skipped, crash-recovery, and quarantine); they disagree in
  the enumerated cases: stdout/done.json vs run.json (ETR-010), canceled
  agent:ask items vs summary (ETR-009b), the terminalization crash window
  (ETR-006), and >500-finding journey counts (ETR-013).
- **Is current HEAD safe to treat as execution-truthworthy?** No. Until
  ETR-001/002/003/005/006/007 are fixed, an operator cannot rely on
  "verified", "completed", or an intact run history without independently
  checking the backend field, the exit path, and the typed stream.

*Audit artifacts (baseline, gate logs, journey outputs, doctored fixtures)
are outside the repository under `/tmp/kuzushi-etr-audit/`. No production
code, test, config, or git state was modified; this file is the audit's only
repository edit.*
