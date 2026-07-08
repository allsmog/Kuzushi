Kuzushi Terminal Cockpit — Product, Architecture & UI Implementation Guide

1. Executive Diagnosis

What Kuzushi already supports (confirmed). The hard, load-bearing infrastructure for a review cockpit already exists:

- A durable review ledger. Finding (crates/kuzushi-core/src/findings/domain/finding_record.rs:63) carries a stable identity (fingerprint, FNV‑1a over rule_id + file_path + start_line, findings/domain/mod.rs:42), a dedup_key (line-bucketed, bucket size 8), evidence, triage, and verification, persisted in SQLite at .kuzushi/v3/index.sqlite3 (findings/persistence/finding_store.rs) in WAL mode.
- Sticky human decisions. Triage is an UPSERT on finding_id (findings/persistence/open/triage_and_verification.rs), so a disposition survives reruns as long as identity matches. Verification is append-only with latest-wins.
- Run + git provenance. Every run mints an id (run_artifacts/run_paths.rs:5), writes a canonical artifact set under .kuzushi/v3/runs/<runId>/, and records RunTargetGitMetadata { sha, branch, dirty } (run_artifacts/running.rs:48) captured via workspace/git_metadata.rs:5.
- A project model, in pieces. RepositoryInventory (workspace/inventory/), context-snapshot.json (context.rs), .kuzushi/threat-model.json with a userEdited guard (capabilities/threat_model/persistence/store.rs), and attack-surface.json together are a project model — just not unified or nested.
- A recommendation engine. capabilities/module_recommender already scores which capabilities to run from the threat model + attack surface + findings.
- A live cockpit. The Ratatui shell has a Workbench split-pane view, an Activity DAG/feed dashboard fed by RunTraceStep v2 (run_artifacts/running.rs:325), a 4-phase journey spine (組 Map / 崩 Hunt / 作 Confirm / 掛 Fix, ui_view_models/journey.rs), and 72 pure view-model builders with plain-text fallbacks.
- A clean control boundary. prepare_tool_input is the single canonical option merge (global → workspace → session → explicit JSON, docs/operator-control-surfaces.md), and model selection is guarded by runtime/policy/no_silent_fallback.rs + scripts/check-model-safety.mjs.
- Prompt override + hashing seed. options/prompt_override.rs resolves prompt text/paths, and RunTraceStep already carries prompt_hash, model, provider (running.rs:351–356).

What is missing (the gaps this guide closes).

1. No unified, nested ProjectModel. Inventory/threat-model/attack-surface are flat and per-target; there is no repo→submodule inheritance, no inherited/local/stale/diff view. Discovery of nested projects stops at target_candidates.rs (.git/.kuzushi children, cap 8) — no submodule/vendored-root awareness.
2. No first-class strategy object. Strategy is implicit (scanner ordering + per-tool promptMode/toolPolicy). There is no StrategyProposal the operator approves, and no StrategyCorrection that persists with author/scope/reason and is explicitly re-applied on rerun.
3. Review-item navigation is thin. FindingListFilter exists but the TUI has no filter grammar spanning run id / SHA / branch / dirty / strategy / owner / changed-files / confidence.
4. The assistant is screen-blind. ask_agent (app/agent_session/ask_agent/agent_dispatch.rs) receives only the typed question + optional FailureToLlmContext. No structured screen context is passed.
5. Prompt stack is not viewable. Hashes are recorded but there is no Prompt Viewer showing base → override → variant → mutation → correction → final, and no approve/reject/edit gate.
6. No in-app revision switching with dirty-worktree safety or cross-revision comparison.
7. Recommendation cost/preflight is not surfaced as an approval card.

What matters most for operator trust and usability. In priority order: (a) provenance you can see — every review item shows its run id + exact SHA + dirty flag, and decisions stick; (b) no hidden behavior — strategies and prompt mutations are proposed and approved, never silently applied, extending the existing no-silent-fallback ethos to strategy/prompt; (c) fast navigation — a filter grammar and revision/nested breadcrumbs so an operator coordinating many passes never loses the thread; (d) parity — everything works in plain/one-shot/batch, not just the TTY.

---
2. Existing Capability Map

Confirmed behavior (code read directly):

┌────────────┬──────────────────────────────────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│  Concern   │                 Location                 │                                                             Symbol                                                              │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Review-ite │ findings/domain/finding_identity.rs      │ BLAKE3 v3 stable identity — rule/tool/context-derived, line numbers excluded                                                     │
│ m identity │                                          │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Dedup      │ findings/domain/mod.rs                   │ compute_dedup_key(file, line, cwe) — line bucket = 8                                                                            │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Review     │ findings/domain/finding_record.rs:63     │ Finding { fingerprint, rule_id, severity, tool, file_path, start_line, static_proof_state, triage, verification, vuln_source,   │
│ item       │                                          │ dedup_key, evidence }                                                                                                           │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Sticky     │ findings/persistence/open/triage_and_ver │                                                                                                                                 │
│ classifica │ ification.rs                             │ record_auto_triage() appends a v3 decision event; save_verification() appends proof events                                      │
│ tion       │                                          │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Classifica │                                          │                                                                                                                                 │
│ tion       │ findings/domain/triage_outcome.rs        │ TriageOutcome { verdict, confidence, rationale, cost_usd }                                                                      │
│ decision   │                                          │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Confirmati │ findings/domain/persisted_results.rs:70  │ PersistedVerification { proof_level, proof_verdict, backend, harness_path, crash_evidence, duration_ms, cost_usd, created_at }  │
│ on result  │                                          │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Run id     │ run_artifacts/run_paths.rs:5             │ new_run_id(prefix) → {prefix}-{unix}-{uuid12}                                                                                   │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Run        │ run_artifacts/ (run_paths.rs,            │ .kuzushi/v3/runs/<id>/{run.json,trace.jsonl,events.jsonl,findings.json,proof.json,failures.json,report.md,artifacts.json,context.j │
│ artifact   │ write_run_artifact_json.rs,              │ son,attack-surface.json,threat-model.json,recommendations.json}; .kuzushi/v3/latest pointer                                        │
│ set        │ run_summary_store.rs)                    │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Git        │ run_artifacts/running.rs:48;             │ RunTargetGitMetadata { sha, branch, dirty }; carried on RunSummary.target_git (line 110)                                        │
│ provenance │ workspace/git_metadata.rs:5              │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Trace step │ run_artifacts/running.rs:325;            │ RunTraceStep { n, kind, verb, label, module_id, parent_step, severity, started_at_ms, latency_ms, cost_usd, model, provider,    │
│  (v2)      │ run_artifacts/trace_handle.rs            │ prompt_hash }; TraceHandle::step().emit(); JsonlSink, BroadcastSink                                                             │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Workspace/ │ workspace/domain/workspace_target.rs     │ WorkspaceTarget { root }, constants .kuzushi/v3/index.sqlite3/config.toml/options.json/models.toml                           │
│ target     │                                          │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Program    │ workspace/domain/program_scope.rs:26     │ ProgramScope { in_scope, out_of_scope }, ScopeVerdict                                                                           │
│ scope      │                                          │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Export     │ workspace/application/export_workspace_f │ WorkspaceExportFormat::{Json,Jsonl,Sarif,Csv,MarkdownBundle}; build_pr_comment (PrCommentInput has git_sha, run_id,             │
│            │ indings.rs:5                             │ changed_files, model)                                                                                                           │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Project    │ workspace/inventory/repository_inventory │                                                                                                                                 │
│ model      │ .rs; context.rs                          │ RepositoryInventory; context-snapshot.json                                                                                      │
│ (context)  │                                          │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Project    │ capabilities/threat_model/persistence/st │                                                                                                                                 │
│ model      │ ore.rs                                   │ persistent_threat_model_path(), load/save_persistent_threat_model(), userEdited guard                                           │
│ (threats)  │                                          │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Recommenda │ capabilities/module_recommender/         │ scores tools from threat model + attack surface + findings                                                                      │
│ tion       │                                          │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Option     │ modules/builtins/with_v2_builtins/execut │                                                                                                                                 │
│ boundary   │ ion.rs:37;                               │ prepare_tool_input(); precedence global→workspace→session→explicit; rejects unknown keys                                        │
│            │ docs/operator-control-surfaces.md        │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Prompt     │ options/prompt_override.rs:4             │ resolve_prompt_override_for_key(); TRIAGE_PROMPT, VERIFY_PROMPT, TAINT_IRIS_PROMPT, CARLINI_THREAT_HUNT_PROMPT                  │
│ override   │                                          │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Model      │ runtime/policy/no_silent_fallback.rs;    │ require_configured_model(), resolve_explicit_model(), normalize_model_spec(); 11 enforced integration points                    │
│ policy     │ scripts/check-model-safety.mjs           │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Budget/cos │ spend/ (SpendLimiter, SpendTicket,       │ --budget triage=…,deep-audit=…; costCapUsd, concurrency options; config session_budget_usd, spend_hard_ceiling_usd              │
│ t          │ Operation); scan_budget.rs               │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Target     │ crates/kuzushi-tui/src/app/onboarding/ta │ discover_target_candidates(), looks_like_target(), candidate_rank() (kuzushi=0,git=1,plain=2, cap 8)                            │
│ discovery  │ rget_candidates.rs:24                    │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Cockpit    │ crates/kuzushi-tui/src/app/view_state/sa │ ShellView (~40 variants), WorkbenchPane::{Source,Center,Findings,Details}                                                       │
│ views      │ st_task_row.rs:81                        │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Journey    │ crates/kuzushi-tui/src/ui_view_models/jo │ 4 phases; current_phase(); footer 組 map 1/4                                                                                    │
│ spine      │ urney.rs                                 │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Assistant  │ app/agent_session/ask_agent/agent_dispat │ ask_agent(); only question + optional FailureToLlmContext                                                                       │
│            │ ch.rs                                    │                                                                                                                                 │
├────────────┼──────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Viz        │ crates/kuzushi-tui/src/scene3d/model.rs; │ VizPage::{AttackSurface,AttackPath,Dfd,Heatmap,ExploitChain}                                                                    │
│ gallery    │  ui_view_models/viz_data.rs              │                                                                                                                                 │
└────────────┴──────────────────────────────────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

Inferred behavior (deduced, flagged as such): the specific per-artifact auto-open triggers; the exact DAG phase ordering inside sast:scan; BroadcastSink's fan-out to the TUI feed; narrow-terminal footer wrapping via Ratatui constraints. These do not affect the design but should be re-verified before implementation.

---
3. Gap Matrix

┌───────────────────┬───────────────────────────────────────────────┬───────────────────────────────────────────────────────────────────────┬─────────────────────────────────────────────┐
│    Requirement    │               Today (confirmed)               │                                  Gap                                  │               Where it lands                │
├───────────────────┼───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Project model     │ Flat inventory + threat-model +               │ No unified model, no nesting, no inherited/local/stale/diff           │ New ProjectModel aggregate +                │
│ mgmt              │ attack-surface per target; userEdited guard   │                                                                       │ NestedProjectScope; ShellView::ProjectModel │
├───────────────────┼───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Review-item       │ FindingListFilter exists; findings/since      │ No grammar over                                                       │ Filter DSL + FindingListFilter extension    │
│ filters           │ verbs                                         │ run/SHA/branch/dirty/strategy/owner/confidence/changed-files          │                                             │
├───────────────────┼───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Run/revision      │ RunSummary.target_git, per-item run id via    │ Item→SHA link is indirect; no cross-revision compare                  │ RunProvenance + TargetRevision; item        │
│ provenance        │ scan_id                                       │                                                                       │ carries run_id+sha                          │
├───────────────────┼───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Nested projects   │ target_candidates.rs (git/kuzushi children)   │ No submodule/vendored discovery, no enter/breadcrumb, no persisted    │ NestedProjectScope, discovery, breadcrumb,  │
│                   │                                               │ nested identity                                                       │ run-artifact field                          │
├───────────────────┼───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Strategy queue    │ Implicit ordering; module_recommender scores  │ No StrategyProposal object, no approve gate, no queue view            │ StrategyProposal + ShellView::StrategyQueue │
├───────────────────┼───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Phase corrections │ promptMode/toolPolicy per tool                │ No persisted correction w/ author/scope/reason; no explicit re-apply  │ StrategyCorrection (corrections.jsonl)      │
├───────────────────┼───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Prompt mutation   │ prompt_override.rs; RunTraceStep.prompt_hash  │ No resolved-stack view, no approve/reject/edit                        │ PromptStack + ShellView::PromptsEditor      │
│                   │                                               │                                                                       │ extension                                   │
├───────────────────┼───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Screen-aware      │ question + failure context only               │ No screen context struct                                              │ ScreenContext model + ask_agent integration │
│ assistant         │                                               │                                                                       │                                             │
├───────────────────┼───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Guided config     │ prepare_tool_input, config.toml, --budget     │ No phase-template config surface tying it together                    │ PhaseTemplate config under existing         │
│                   │                                               │                                                                       │ boundary                                    │
├───────────────────┼───────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┼─────────────────────────────────────────────┤
│ Terminal/plain    │ renderer/plain.rs, 72 view-models             │ New views must ship plain builders + tests                            │ Each milestone includes plain output        │
│ parity            │                                               │                                                                       │                                             │
└───────────────────┴───────────────────────────────────────────────┴───────────────────────────────────────────────────────────────────────┴─────────────────────────────────────────────┘

---
4. Proposed Product Architecture

Design rule: every new type is a thin aggregation or extension of what exists, persisted under <target>/.kuzushi/, additive to current schemas, and mode-agnostic (built by a pure function, consumed by scan/shell/run alike). No new env vars — all knobs flow through prepare_tool_input and config.toml.

4.1 The twelve types

ContextFeed — the input side of a project model. Wraps the existing collectors (collect_agentic_repo_inventory(), context-snapshot.json, recon intake) as a provenance-tagged stream of context items rather than one blob. Each item records source (inventory / recon-import / attach / diff-scope), a content hash, and the TargetRevision it was gathered at. Persistence: .kuzushi/v3/context/feed.jsonl (append-only) + the existing context-snapshot.json as the materialized head. Relationship: feeds ProjectModel.

ProjectModel — the unified, browsable aggregate over RepositoryInventory + threat-model doc + attack-surface + derived summaries, keyed by NestedProjectScope. Sections are typed (inventory, frameworks, entrypoints, threat_model, attack_surface, assumptions). Each section carries origin: Inherited | Local | Refreshed, a content_hash, and a built_at_revision: TargetRevision. Staleness = built_at_revision.sha != current head or an input content hash changed. Persistence: .kuzushi/v3/project-model/<scope-id>.json; the repo-root scope reuses today's .kuzushi/threat-model.json + context-snapshot.json as its section sources, so no data is duplicated. Relationship: recommends StrategyProposals; provides the "inherited vs local vs stale" data the UI renders.

NestedProjectScope — extends WorkspaceTarget with parent: Option<ScopeId>, kind: Root | Submodule | VendoredRoot | DependencyRoot, rel_path, and inherited_sections: Vec<SectionKey>. Discovery generalizes discover_target_candidates() to also parse .gitmodules, detect vendored dirs (reuse workspace/inventory/generated_vendor_path.rs), and flag major dependency roots. Inheritance is resolved at read time: a nested model overlays local sections on top of the parent's, marking each as Inherited or Local. Persistence: .kuzushi/v3/project-model/scopes.json (the scope tree). Relationship: keys ProjectModel, appears in breadcrumbs, and is written into run artifacts.

TargetRevision — canonicalizes git identity for a run/item: { sha, branch, dirty, worktree_hash? }. This is the existing RunTargetGitMetadata (running.rs:48) promoted to a shared value type used by runs and the revision switcher. worktree_hash (a hash of the dirty diff) makes dirty runs distinguishable and reproducible-by-note. Persistence: embedded in RunProvenance and on each ReviewLedgerEntry.

PhaseRun — one execution of one phase, wrapping a runId with { phase: ContextPhase|ProjectModelPhase|ReviewPhase|ClassificationPhase|ConfirmationPhase|ReportPhase, scope: ScopeId, revision: TargetRevision, strategies: Vec<StrategyId>, prompt_stack_ref, status, started_at, cost_usd }. It is the join between the journey spine and the artifact store. Persistence: .kuzushi/v3/runs/<runId>/phase.json + an index at .kuzushi/v3/phase-runs.jsonl. Relationship: produced by the state machine (§6); consumed by the Run/Revision Timeline.

StrategyProposal — a proposed, operator-approved approach for a phase, emitted by an evolved module_recommender: { id, phase, base_strategy, recommended_strategy, rationale, expected_cost_usd, expected_runtime, prerequisites: Vec<Preflight>, resource_risk: Low|Med|High, status: Proposed|Approved|Rejected }. Preflight checks reuse existing signals (project size from inventory, presence of CodeQL/Joern indexes, budget headroom from SpendLimiter). Never auto-applied — mirrors the no-silent-fallback contract. Persistence: .kuzushi/v3/strategy-queue.jsonl plus optional producer-declared run artifacts when a run exports a strategy proposal.

StrategyCorrection — an operator override of a phase's chosen strategy, before or after it runs: { id, target_phase, from_strategy, to_strategy, prompt_mutation_ref?, scope: Run|Scope|Workspace, author, timestamp, reason }. Reruns apply corrections explicitly and visibly. Persistence: append-only .kuzushi/v3/corrections.jsonl (workspace-scoped) and mirrored into the runId that applied it. Relationship: alters a PhaseRun's strategies and can carry a PromptStack mutation.

PromptStack — the resolved prompt lineage for a phase/tool: { base, project_override, variant, mutation, correction, final_rendered, hashes: {each_layer} }. Built from options/prompt_override.rs resolution plus the correction/variant layers; the final hash is what already lands in RunTraceStep.prompt_hash. Operators approve / reject / edit a mutation before it's used. Persistence: .kuzushi/v3/runs/<runId>/prompt-stack.json; the final hash also on PhaseRun. Relationship: referenced by StrategyCorrection and PhaseRun; rendered by the Prompt Viewer.

ReviewLedgerEntry — the review item, i.e. today's Finding with three additive provenance fields surfaced: run_id, revision: TargetRevision, and scope: ScopeId. Identity, dedup, evidence, and sticky decisions are unchanged (fingerprint / dedup_key). Merged duplicates preserve every contributing source: add a sources: Vec<{ run_id, tool, strategy, fingerprint }> column so a merge never discards which pass found it. Persistence: .kuzushi/v3/index.sqlite3 (extend findings + a finding_sources table).

ClassificationDecision — today's TriageOutcome, unchanged in shape (verdict, confidence, rationale, cost_usd), but explicitly modeled as sticky-by-fingerprint with an owner field added for the owner filter. Persistence: triage table (already UPSERT-sticky).

ConfirmationResult — today's PersistedVerification (proof ladder, verdict, backend, evidence), unchanged. It is the "moves to confirmation" output of the Confirmation phase. Persistence: verifications table (append-only, latest-wins).

RunProvenance — the per-run header joining everything: { run_id, scope: NestedProjectScope, revision: TargetRevision, phase, strategies: Vec<StrategyId>, prompt_hashes, model, provider, cost_usd, started_at }. This is RunSummary (running.rs:57) with scope + strategies + prompt_hashes added (all optional → backward-compatible). Persistence: .kuzushi/v3/runs/<runId>/run.json.

4.2 Relationships (one diagram in words)

ContextFeed → materializes ProjectModel (keyed by NestedProjectScope, stamped with TargetRevision). ProjectModel → emits StrategyProposals → operator approves → each becomes part of a PhaseRun (which pins a TargetRevision + PromptStack). A StrategyCorrection can rewrite a PhaseRun's strategy and mutate its PromptStack. Running a PhaseRun writes RunProvenance + produces ReviewLedgerEntrys, each stamped with run_id + revision + scope and carrying sources[]. Entries flow to ClassificationDecision (sticky) then ConfirmationResult, then into reports/follow-up.

4.3 Persistence summary (all under <target>/.kuzushi/)

.kuzushi/
  latest                      → newest runId (exists)
  v2/
    index.sqlite3          findings + finding_sources + triage + verifications (extend)
    config.toml               phase templates, budgets, model (exists; extend)
    options.json              per-tool options (exists)
    context/feed.jsonl        ContextFeed (new)
    project-model/
      scopes.json             NestedProjectScope tree (new)
      <scope-id>.json         per-scope ProjectModel (new; root reuses existing docs)
    phase-runs.jsonl          PhaseRun index (new)
    strategy-queue.jsonl      StrategyProposal queue (new)
    corrections.jsonl         StrategyCorrection log (new)
  threat-model.json           root ProjectModel threat section (exists; userEdited guard)
  context-snapshot.json       root ProjectModel inventory section (exists)
  runs/<runId>/
    run.json                  RunProvenance (extend RunSummary)
    phase.json                PhaseRun (new)
    strategy.json             approved StrategyProposal (new)
    prompt-stack.json         PromptStack (new)
    trace.jsonl, findings.json, proof.json, report.md ...  (exist)

---
5. Terminal UI Specification

Global chrome. Top bar breadcrumb: Kuzushi · <repo> ▸ <nested-scope> ▸ <rev> ▸ <phase> · LIVE. Phase rail below it: [組 map ●]─[崩 hunt ○]─[作 confirm ○]─[掛 fix ○] (reuse journey.rs glyphs and JourneyPhaseState Done ✓ / Current ● / Pending ○). Status footer chips: phase:map 1/4, rev:abc1234* (* = dirty), scope:submodule/foo, strat:on, cost:$0.42/$2.50, filter:3 active. Every chip is truthful state, not decoration (honoring the signifier↔state invariant in memory).

5.1 Priority screens

Workbench (ShellView::Workbench, extend). Keep the 4-pane Source | Center | Findings | Details (WorkbenchPane, Tab cycles). Add the breadcrumb + phase rail as the top two rows and a filter line above Findings. Center pane gains a mode toggle: code context / DFD / project-model section so an operator can read inherited context without leaving.

Review Items (evolve ShellView::Findings). A dense table:
STATE  CONF  RANK  ITEM                    FILE:LINE          TOOL/STRAT       RUN      REV
●new   ○     high  Unvalidated input path  auth/login.rs:88   taint-iris/deep  r-8f2..  abc1234*
✓conf  ✓tp   crit  Missing authz check     api/orders.rs:24   systems-hunt     r-8f2..  abc1234
◐dup(3)-      med  Resource lifetime       core/pool.rs:51    uaf-hunt/merge   r-7a1..  9de5f01
Columns: state, confirmation state, rank, title, file:line, tool/strategy, run (short), revision (short, *=dirty). ◐dup(N) means N preserved sources; Enter expands them. Right/detail pane shows evidence, sources[], classification + confirmation history across runs.

Project Model (ShellView::ProjectModel, new). Left: scope tree (root → submodules/vendored). Right: sections with an origin gutter — ⤓ inherited, ◆ local, ⚠ stale. Selecting a stale section offers refresh; selecting an inherited one offers override (fork to local). A diff action shows inherited-vs-local or built-at-revision-vs-head side by side.

Strategy Queue (ShellView::StrategyQueue, new). One row per StrategyProposal:
PHASE    BASE→RECOMMENDED         COST    RUNTIME  PREREQS         RISK   STATUS
hunt     quick → deep-semantic    ~$0.80  ~6m      ✓idx ✓budget    med    proposed
confirm  standard → staged        ~$0.20  ~2m      ⚠no-sandbox     low    proposed
a approve, x reject, c correct (opens correction form: to-strategy, scope, reason), p preview prompt stack. Heavy/deep proposals are only shown when preflight passes; when size/index/budget make them unreasonable the row is dimmed with the reason and a cheaper staged alternative is recommended first. Nothing runs without a.

Nested Project Picker (extend ShellView::TargetPicker). Lists root + discovered submodules/vendored/dependency roots with kind badges and last-run revision. Enter enters the scope (sets breadcrumb, loads that scope's ProjectModel). Risky nothing here — pure navigation.

Run / Revision Timeline (evolve ShellView::Runs). Grouped by revision:
abc1234 (main, dirty)   r-8f2..  hunt+confirm   14 items   $0.61   2h ago
9de5f01 (main)          r-7a1..  full sweep     31 items   $1.20   1d ago
d diff two selected revisions' review items; Enter opens the run (replay/trace already exist).

Prompt Viewer (extend ShellView::PromptsEditor). Stacked, collapsible layers with per-layer hash:
base            #a1b2  (read-only)
project-override#c3d4  .kuzushi/prompts/triage/run.md
variant          —
mutation        #e5f6  [pending approval]  (a)pprove (x)reject (e)dit
correction      #0718  by operator · scope:run · "tighten to authz only"
final           #99aa  → recorded in trace.prompt_hash
Editing a mutation re-hashes and re-renders final live. Approve/reject is required before the phase can consume a mutated prompt.

Activity (exists) and Assistant Chat (ShellView::AgentChat, extend with screen context per §5.4).

5.2 Keybindings (consistent with current conventions)

Global: Tab cycle pane/focus, j/k/g/G/PgUp/PgDn scroll, Enter select, b/Esc back, / open filter, : command, ? help. Screen-specific: Review Items f focus filter, o set owner, m merge-view; Strategy Queue a/x/c/p; Project Model r refresh, O override, d diff; Timeline d diff revisions, R switch revision (confirm dialog); Prompt Viewer a/x/e. Revision switch and any dirty-worktree action route through a confirmation_keys.rs-style Y/N/Always gate.

5.3 Filter grammar

A compact key:value DSL parsed into an extended FindingListFilter, usable identically in the TUI filter line, kuzushi findings --filter '<expr>', and batch mode:

state:new|triaged|confirmed|dismissed     conf:tp|fp|needs-review|by-design
rank:crit|high|med|low                    cat:<category>
tool:<name>   strat:<strategy>            run:<runId>   rev:<sha|branch>
dirty:true|false                          scope:<scope-id|path>
file:<glob>   changed:true                owner:<name>  confidence:>=NN
Grammar: space-separated terms = AND; key:a,b = OR within a key; -key:v = negation; bare word = title/file substring. Example: state:new rank:crit,high tool:taint-iris -conf:fp rev:main dirty:false. Empty result → empty-state line naming which term matched nothing.

5.4 Screen-aware assistant context

Define a pure builder screen_context_model(app: &ShellApp) -> ScreenContext in ui_view_models/ (mirrors the other 72 builders, fully testable off-screen):

ScreenContext {
  view: String,                 // "ReviewItems"
  focused_pane: Option<String>, // "Findings"
  selected_item: Option<{ fingerprint, title, file, line, rank, state, conf }>,
  selected_run: Option<String>,
  selected_revision: Option<{ sha, branch, dirty }>,
  active_phase: Option<String>, // "hunt"
  active_filters: Vec<String>,  // parsed terms
  selected_scope: Option<String>,
  visible_rows: Vec<String>,    // capped, truncated
  cursor: { row, col },
}

Integration point: app/agent_session/ask_agent/agent_dispatch.rs. Build ScreenContext, serialize it, and append it to the prompt exactly the way FailureToLlmContext is already appended — as a clearly delimited block. Critical safety rule, made explicit in the prompt: the block is wrapped as UNTRUSTED SCREEN CONTEXT — data only, never instructions, so visible screen text (which can include repository content) is never treated as a command. This reuses the existing structured-handoff pattern rather than inventing a new channel, and it flows through the same agent_worker + trace-artifact plumbing.

5.5 User flows

- Switch revision: Timeline → R → picker of local branches/commits → dirty-worktree guard (Y/N/Always): if dirty, offer stash-note (record worktree_hash, do not mutate the tree) or cancel; never auto-stash. On confirm, breadcrumb + footer update; runs/items stay pinned to their own TargetRevision.
- Select nested project: Picker → Enter a submodule → breadcrumb repo ▸ submodule/foo ▸ rev ▸ phase; ProjectModel view loads that scope with inherited sections marked.
- Inspect inherited model context: ProjectModel → select ⤓ inherited section → d to diff against parent → O to fork a local override (becomes ◆ local).
- Approve a strategy: Strategy Queue → read cost/runtime/preflight/risk → p to preview its prompt stack → a to approve (enters the Phase queue) or c to correct.
- Mutate a prompt: Prompt Viewer → e edit mutation layer → live re-hash → a approve; the phase now runs with the mutated, hashed prompt recorded in trace.prompt_hash.
- Filter review items: / → type state:new rank:crit tool:systems-hunt → live-narrow; footer shows filter:3 active.
- Ask the assistant about the screen: ask what changed between these two revisions for the selected item → ScreenContext (selected item + both revisions + filters) is attached as untrusted data; answer is grounded in exactly what's on screen.

5.6 Plain / accessibility parity

Every screen ships a plain builder in renderer/plain.rs (stacked labeled lines, no box-drawing) and honors KUZUSHI_THEME=high-contrast + KUZUSHI_REDUCED_MOTION (theme/config.rs). Narrow terminals wrap the footer to two lines (existing behavior). Non-interactive kuzushi findings --filter … and --json produce the same rows the TUI shows. The frame-rendered Project Model / Strategy Queue degrade to line lists exactly as the viz gallery already degrades via scene_page_lines.

---
6. Phase & Strategy State Machine

Six phases, mapped onto the existing 4-phase journey so the spine stays honest:

┌─────────────────────┬───────────────┬──────────────────────────┬─────────────────────────────────────────┐
│ State-machine phase │ Journey phase │         Produces         │              Backing code               │
├─────────────────────┼───────────────┼──────────────────────────┼─────────────────────────────────────────┤
│ Context             │ 組 Map        │ ContextFeed              │ inventory collectors, recon intake      │
├─────────────────────┼───────────────┼──────────────────────────┼─────────────────────────────────────────┤
│ Project-model       │ 組 Map        │ ProjectModel sections    │ threat_model, attack_surface            │
├─────────────────────┼───────────────┼──────────────────────────┼─────────────────────────────────────────┤
│ Review              │ 崩 Hunt       │ ReviewLedgerEntrys       │ sast:scan review passes                 │
├─────────────────────┼───────────────┼──────────────────────────┼─────────────────────────────────────────┤
│ Classification      │ 作 Confirm    │ ClassificationDecision   │ triage:run                              │
├─────────────────────┼───────────────┼──────────────────────────┼─────────────────────────────────────────┤
│ Confirmation        │ 作 Confirm    │ ConfirmationResult       │ verify:finding                          │
├─────────────────────┼───────────────┼──────────────────────────┼─────────────────────────────────────────┤
│ Report/follow-up    │ 掛 Fix        │ reports, follow-up items │ export, build_pr_comment, patch:finding │
└─────────────────────┴───────────────┴──────────────────────────┴─────────────────────────────────────────┘

current_phase() in journey.rs already derives Map→Hunt→Confirm→Fix from disk reality (artifacts present, findings count, confirmed count); the six-phase model refines it without changing that derivation — Context vs Project-model is "inventory present but model not built," Classification vs Confirmation is "triaged but not verified."

How strategies feed classification. A StrategyProposal approved for the Review phase pins which review-pass engines and promptMode/toolPolicy run; each produced ReviewLedgerEntry records its originating strategy in sources[]. The Classification phase can then filter/route by strategy (e.g. classify deep-semantic items first), and the strategy tag is a first-class filter key.

How corrections alter a phase strategy. A StrategyCorrection names target_phase + from→to + scope + reason. On the next PhaseRun for that phase/scope, the resolver applies matching corrections explicitly: the Strategy Queue shows base → recommended → corrected, and RunProvenance.strategies records the corrected set. Corrections at Workspace scope persist across reruns; Run scope applies once.

How stop-after-phase works. PhaseTemplate.stop_after: Option<Phase> (config). The runner executes phases in order and halts after the named one, writing PhaseRun.status = StoppedByPolicy. This reuses the existing DAG-gating idea (pipeline:approval-before-verification) but as an operator-declared boundary, not hidden behavior. Plain/batch modes honor it identically.

How resume works. Resume reads phase-runs.jsonl for the scope+revision, finds the last completed phase, and re-enters at the next one — reusing the existing resume [runId] verb and .kuzushi/v3/latest pointer. Because decisions are sticky by fingerprint, resuming after Review does not re-triage already-classified items. If the revision changed since the paused run, resume surfaces a guard (items were produced at abc1234; you are now at 9de5f01 — compare / continue / cancel).

---
7. Implementation Guide (small, testable slices)

M1 — TargetRevision + item provenance surfacing. Promote RunTargetGitMetadata to a shared TargetRevision value type; add run_id, revision, scope to the review-item read model and the Review Items table. Files: run_artifacts/running.rs, workspace/git_metadata.rs, findings/domain/finding_record.rs, ui_view_models/findings.rs. Data: additive columns (nullable) on findings; migration is a no-op ALTER. UI: run/rev columns + footer rev: chip. Tests: provenance round-trips; dirty flag renders *. Accept: every item shows the run + exact SHA that produced it.

M2 — Filter grammar. Parser → extended FindingListFilter; wire into TUI filter line + kuzushi findings --filter + batch. Files: new findings/application/filter_grammar.rs, ui_view_models/findings.rs, CLI adapter. Tests: pure parser table (AND/OR/negation/>=), empty-state naming. Accept: identical results across shell/run/batch for the same expression.

M3 — NestedProjectScope discovery + picker + breadcrumb. Generalize discover_target_candidates() to parse .gitmodules, vendored roots, dependency roots; persist scopes.json; add breadcrumb + enter-scope. Files: app/onboarding/target_candidates.rs, new workspace/domain/nested_scope.rs, TUI picker/breadcrumb. Tests: discovery on a fixture repo-with-submodule; scope identity persists. Accept: operator can enter a submodule and the breadcrumb reflects it.

M4 — ProjectModel aggregate + view. Aggregate inventory + threat-model + attack-surface behind ProjectModel, keyed by scope, with origin + staleness; new ShellView::ProjectModel. Files: new workspace/application/project_model.rs, ui_view_models/project_model.rs, renderer + plain. Data: project-model/<scope>.json; root reuses existing docs (no duplication). Tests: inherited-vs-local resolution; stale detection by revision + content hash. Accept: inherited/local/stale/diff all render, incl. plain.

M5 — StrategyProposal + queue + approval gate. Evolve module_recommender to emit proposals with cost/runtime/preflight/risk; ShellView::StrategyQueue; approve/reject. Files: capabilities/module_recommender/, new strategy module, TUI view. Data: strategy-queue.jsonl, runs/<id>/strategy.json. Tests: heavy proposals hidden when preflight fails; nothing runs without approval. Accept: no strategy executes un-approved; costs shown before run.

M6 — StrategyCorrection. Correction form + corrections.jsonl; resolver applies on rerun and records base→recommended→corrected. Files: new strategy/correction.rs, resolver hook in scan prepare, TUI form. Tests: correction persists w/ author/scope/reason; rerun applies exactly the corrected set. Accept: lineage visible; workspace-scope corrections survive reruns.

M7 — PromptStack viewer + mutation gate. Assemble layered stack from prompt_override.rs + variant/correction; per-layer hashes; approve/reject/edit; final hash → trace.prompt_hash (already exists). Files: options/prompt_override.rs, new prompt_stack.rs, PromptsEditor view. Tests: hash stability; edit re-hashes final; unapproved mutation blocks the phase. Accept: stack is reproducible and reviewable.

M8 — Screen-aware assistant. screen_context_model() builder + untrusted-block integration in ask_agent. Files: new ui_view_models/screen_context.rs, agent_session/ask_agent/agent_dispatch.rs. Tests: builder snapshot per view; injection-safety (screen text with imperative content is not obeyed). Accept: assistant answers reference the correct selected item/run/revision/filters.

M9 — Revision switching + cross-revision compare. R switch with dirty guard (stash-note, never auto-mutate); Timeline d diff. Files: new workspace/application/revision_switch.rs, Timeline view, confirmation gate. Tests: dirty guard blocks unsafe switch; items stay pinned to their revision. Accept: risky git ops require explicit confirm; compare works.

M10 — Guided phase config + parity. PhaseTemplate (budgets, concurrency, strategy caps, confirmation depth, prompt variants, stop-after) under config.toml + prepare_tool_input; ensure scan/run/batch parity. Files: config schema, docs/operator-control-surfaces.md, docs/assessments/mode-parity.md. Tests: template drives all three modes identically; no new env var. Accept: one config surface, documented, parity-checked.

Sequence M1→M2 first (cheapest trust win), then M3/M4 (nesting + model), then M5/M6 (strategy), M7/M8 (prompt + assistant), M9/M10 last.

---
8. Test Plan

- Pure domain / view-model: screen_context_model, project_model origin/stale resolution, filter-grammar parser, journey/phase derivation, prompt-stack assembly — all off-screen, mirroring existing ui_view_models tests.
- Artifact persistence: RunProvenance/PhaseRun/StrategyProposal/StrategyCorrection/PromptStack round-trip; additive-schema backward-compat (old run.json/RunTraceStep still load); finding_sources migration preserves all sources on merge.
- Filter tests: AND/OR/negation/>=, unknown-key rejection (consistent with prepare_tool_input rejecting unknown keys), empty-state naming, parity across shell/run/batch.
- Strategy queue: proposal ordering, preflight gating (heavy hidden when size/index/budget unreasonable), approval required before execution, corrected-set applied on rerun.
- Git revision: dirty detection, worktree_hash stability, dirty-switch guard blocks unsafe switch, items stay pinned, cross-revision diff.
- Nested project inheritance: submodule/vendored/dependency discovery on a fixture; inherited vs local overlay; override forks to local; parent change marks child stale.
- Prompt hash: per-layer + final hash stability; edit re-hashes; final equals trace.prompt_hash; same inputs → same hash.
- Assistant screen-context: builder snapshots per view; injection safety — imperative text in visible_rows/selected_item is treated as data, not obeyed (extend the untrusted-block handling already used for failure context).
- Terminal rendering: Ratatui buffer tests for Review Items table, Strategy Queue, Project Model panes; breadcrumb + phase rail + chips; narrow-terminal footer wrap; high-contrast + reduced-motion.
- Plain output: every new view's renderer/plain.rs builder; --json/--filter parity with TUI rows.
- Preflight / resource-risk: cost/runtime estimates vs SpendLimiter headroom; index-present detection; risk tiering; budget-exceeded surfaces as a halt card, not a silent skip.

---
9. Risks & Open Questions

- Cutover risk (moderate). v3 removes legacy fingerprint migrations and treats stale v2 artifacts as disposable; rebuild projections from the event log/CAS path instead of carrying additive compatibility code.
- Artifact compatibility. RunSummary and RunTraceStep are the compatibility surface; keep every new field Option/additive and version the run header. Do not repurpose existing fields.
- UI complexity. Ten priority screens risk overwhelming the operator. Mitigate by making the Workbench the hub (breadcrumb + rail + filter) and keeping each new view single-responsibility with a plain fallback; reuse Tab/j/k/Enter everywhere so muscle memory transfers.
- Resource cost. Deeper strategies and cross-revision runs multiply LLM spend. The StrategyProposal cost/preflight gate + SpendLimiter caps + stop-after-phase are the controls; never auto-escalate — mirror the no-silent-fallback contract for strategy and prompt.
- Nondeterministic runs. Two runs at the same SHA can yield different items/decisions. Sticky-by-fingerprint decisions and sources[] preservation reduce churn; the Timeline/diff makes divergence visible rather than hidden. Record model/provider/prompt_hash (already on the trace) so a result is explainable even when not bit-reproducible.
- Nested inheritance semantics. Open question for product: when a parent section refreshes, do child inherited sections auto-refresh, or just mark stale and wait for the operator? Recommend mark-stale-then-operator-refresh (no silent mutation), but confirm.
- Decisions needing product input: (1) revision-switch dirty policy — stash-note vs require-clean (recommend stash-note, never auto-stash); (2) correction default scope — Run vs Workspace (recommend Run, opt-in to Workspace); (3) whether merged-duplicate stickiness follows the surviving fingerprint or the union of sources when identities diverge; (4) how much visible_rows context to send the assistant given token cost (recommend a small, capped, truncated slice).

---
Output-rule compliance: no code patches, no dangerous examples, no live-target procedures, no hidden automatic behavior, no silent model/runtime or strategy fallback, no per-mode behavior duplication (everything routes through prepare_tool_input / shared builders), no undocumented env vars (knobs go in config.toml + options), and no silent state mutation (strategies, prompts, and revision switches are all operator-approved). File references throughout are concrete and point at the real Kuzushi tree.

If you'd like, I can drop this into docs/design/terminal-cockpit.md so it lives alongside the existing docs/architecture and docs/assessments material — say the word and I'll write the file (docs only, no code touched).
