//! Real-data presentation models for the five durable cockpit phase pages.
//!
//! These DTOs project persisted artifacts, findings, and application state.
//! They do not infer progress, proof, application, or remediation truth that
//! Kuzushi has not actually observed.

use super::{
    context_strip_model, journey_model, AttackSurfaceRiskModel, AttackTree, CheckpointDrift,
    ContextSnapshotModel, DfdModel, FindingDetailModel, FindingsModel, JourneyModel,
    JourneyPhaseStatus, PatchReviewModel, ProjectModel, ReportPreviewModel, ReviewQueueModel,
    RiskByModule, TaintFlowPath, ThreatPatchCardModel, WorklistViewModel,
};
#[cfg(test)]
use crate::{phase_attempt_outcome_from_label, phase_result_policy};
use crate::{InputMode, ShellApp, ShellView};
use kuzushi_core::WorkflowPhase;

mod composition;
mod confirm;
mod layout;
#[cfg(test)]
mod layout_matrix_tests;
mod map;
mod phase_bodies;
mod result_controls;
mod scan;
#[cfg(test)]
use result_controls::result_action_label;
use result_controls::result_action_labels_for;
pub(crate) use result_controls::result_keybindings;

pub(crate) use composition::{Composition, DrawerSize, DrawerSpec, SurfaceRole};
mod chain_artifacts;
mod identity;
mod trace_evidence;
pub(crate) use confirm::investigation_verify_command;
use confirm::prove_phase_model;
pub(crate) use layout::{
    phase_presentation_plan, phase_surface_specs, AttentionMode, LayoutDensity,
    PhasePresentationPlan, PhaseSurfaceId, PlannedPhaseSurface, SurfaceInteraction, SurfaceState,
};
use map::map_phase_model;
pub(crate) use map::{
    map_context_fit, map_gallery_is_canvas, ready_map_gallery_is_primary, MapContextFit,
};
use phase_bodies::{fix_phase_model, review_phase_model};
use scan::scan_phase_model;
pub(crate) use scan::study::{ScanStudyModel, ScanStudyQueue};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PhaseCockpitModel {
    pub(crate) phase: WorkflowPhase,
    pub(crate) header: EngagementHeaderModel,
    pub(crate) body: PhaseCockpitBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhaseResultCardModel {
    pub(crate) attempt_id: String,
    pub(crate) outcome: String,
    pub(crate) emphasis: crate::PhaseResultEmphasis,
    pub(crate) compact_summary: String,
    pub(crate) detail: String,
    pub(crate) detail_rows: Vec<crate::app::PhaseResultDetailRow>,
    pub(crate) semantic_keys: std::collections::BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
    pub(crate) actions: Vec<kuzushi_core::workflow_attempts::PhaseResultAction>,
    pub(crate) control_hint: String,
    pub(crate) recommended: String,
}

impl PhaseResultCardModel {
    pub(crate) fn has_result_actions(&self) -> bool {
        !self.actions.is_empty()
    }
}

impl PhaseCockpitModel {
    pub(crate) fn selected_finding_detail(&self) -> Option<&FindingDetailModel> {
        match &self.body {
            PhaseCockpitBody::Review(model) => model.finding.as_ref(),
            PhaseCockpitBody::Prove(model) => model.finding.as_ref(),
            PhaseCockpitBody::Fix(model) => model.finding.as_ref(),
            PhaseCockpitBody::Map(_) | PhaseCockpitBody::Scan(_) => None,
        }
    }

    /// Fix page whose selected finding has neither a patch draft nor a
    /// remediation lifecycle record: the next remediation step is a draft.
    pub(crate) fn selected_finding_awaits_patch_draft(&self) -> bool {
        match &self.body {
            PhaseCockpitBody::Fix(model) => model.awaits_patch_draft(),
            _ => false,
        }
    }
}

impl FixPhaseModel {
    fn awaits_patch_draft(&self) -> bool {
        self.finding.is_some()
            && self.patch.is_none()
            && self.remediation.stage == RemediationLifecycleStage::NotDrafted
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PhaseCockpitBody {
    Map(MapPhaseModel),
    Scan(ScanPhaseModel),
    Review(ReviewPhaseModel),
    Prove(ProvePhaseModel),
    Fix(FixPhaseModel),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScanPhaseModel {
    pub(crate) study: Option<ScanStudyModel>,
    pub(crate) scope: String,
    pub(crate) plan: String,
    pub(crate) attempt: Option<ScanAttemptModel>,
    pub(crate) engine_outcomes: Vec<ScanEngineOutcomeModel>,
    pub(crate) empty_hint: Option<String>,
    /// Present while a scan run is in flight. Drives the operational-columns
    /// dashboard; live trace output stays in Run Focus, this only names the
    /// run so the resting panes read as "in progress", not stale.
    pub(crate) live: Option<LiveScanModel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveScanModel {
    pub(crate) run_id: Option<String>,
    pub(crate) stage: String,
    pub(crate) findings: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScanAttemptModel {
    pub(crate) attempt_id: Option<String>,
    pub(crate) run_id: String,
    pub(crate) run_refs: Vec<String>,
    pub(crate) outcome: String,
    pub(crate) disposition: String,
    pub(crate) freshness: String,
    /// The findings this attempt is credited with, counted the way the
    /// `severity_counts` beside it are counted. On the store-backed paths
    /// that means distinct ledger findings, not producer observations.
    pub(crate) findings: Option<u64>,
    /// Raw producer observations the runs recorded emitting, set only when
    /// corroboration folded several of them into fewer findings. Without it
    /// a panel prints one number as "findings" and breaks the other down.
    pub(crate) findings_observed: Option<u64>,
    pub(crate) findings_added: Option<u64>,
    pub(crate) findings_updated: Option<u64>,
    /// Severity buckets for the attempt's findings, highest band first,
    /// zero buckets omitted. Empty when severity was never recorded — the
    /// page renders no chips rather than inventing zeros.
    pub(crate) severity_counts: Vec<(String, u64)>,
    pub(crate) artifact_count: usize,
    pub(crate) artifact_paths: Vec<String>,
    pub(crate) duration_secs: Option<u64>,
    pub(crate) cost_usd: Option<f64>,
    pub(crate) cost_complete: Option<bool>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanEngineOutcomeModel {
    /// Operator-facing verb-phrase label.
    pub(crate) engine: String,
    /// Raw registry key for engine identity. Reruns use the saved owning
    /// operation, including its scope and options.
    pub(crate) tool_key: Option<String>,
    pub(crate) outcome: String,
    pub(crate) run_ref: Option<String>,
    pub(crate) detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EngagementHeaderModel {
    /// Persisted phase represented by this durable page.
    pub(crate) phase: WorkflowPhase,
    /// Reality-derived engagement phase. Page selection may differ and never
    /// mutates this value.
    pub(crate) reality_phase: Option<WorkflowPhase>,
    pub(crate) checkpoint_drift: Option<CheckpointDrift>,
    pub(crate) target: String,
    pub(crate) context: String,
    pub(crate) model: String,
    /// Active immutable threat-model lineage/revision chip. Present only on
    /// Map so it cannot be confused with the configured runtime model.
    pub(crate) threat_model: Option<String>,
    pub(crate) module: String,
    pub(crate) cost: kuzushi_core::runtime::RuntimeCostReport,
    pub(crate) cost_invalid: bool,
    pub(crate) budget_usd: Option<f64>,
    pub(crate) liveness: super::WorkLiveness,
    pub(crate) finding_filter: Option<String>,
    pub(crate) phase_rail: Vec<JourneyPhaseStatus>,
    pub(crate) next_action: String,
    pub(crate) next_tools: String,
    pub(crate) result_card: Option<PhaseResultCardModel>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MapPhaseModel {
    pub(crate) context: ContextSnapshotModel,
    pub(crate) project: ProjectModel,
    pub(crate) attack_surface: Option<AttackSurfaceRiskModel>,
    pub(crate) hot_modules: RiskByModule,
    pub(crate) worklist: WorklistViewModel,
    pub(crate) next_scans: NextScansState,
    pub(crate) dfd: DfdModel,
    pub(crate) threat_model_freshness: super::ThreatModelFreshnessModel,
    pub(crate) empty_hint: Option<String>,
    pub(crate) recorded_context_issue: Option<String>,
    /// Set on very large, still-undecomposed repositories: the NEXT ACTION
    /// card offers a scope proposal alongside whole-repository planning.
    pub(crate) scope_suggestion: Option<String>,
}

/// Coverage-ledger scan recommendations shown inside the HOT MODULES pane.
/// `Pending` draws nothing: the fold runs off-frame in the hydration worker
/// and the pane must not flash placeholder chrome while it loads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NextScansState {
    Pending,
    Ready(Vec<NextScanRow>),
    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NextScanRow {
    pub(crate) scope: String,
    pub(crate) phase: String,
    pub(crate) reason: String,
    pub(crate) evidence: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReviewPhaseModel {
    pub(crate) trace: Option<TraceEvidenceModel>,
    pub(crate) comparison_control: Option<String>,
    pub(crate) review: ReviewQueueModel,
    pub(crate) finding: Option<FindingDetailModel>,
    pub(crate) selection_disclosure: Option<SelectionDisclosureModel>,
    /// Recommender follow-up passes shown as the Next-Investigation-Plan
    /// drawer; the operator authorizes each pass, nothing runs on its own.
    pub(crate) next_plan: NextScansState,
    /// The Attack Chains screen (`C`): chain artifacts composed over the SET
    /// of confirmed findings, plus grounded chains from `exploit-chain:scan`.
    pub(crate) chains: Option<ChainArtifactsModel>,
}

/// Chains are artifacts produced by a transformation over the triaged result
/// set, not a visualization: each candidate names its constituent findings
/// by alias, and carries the triage mutation the composition implies. The
/// mutation stays advisory copy until the core chain-triage pass exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainArtifactsModel {
    pub(crate) confirmed_count: usize,
    /// `target …@rev · threat model @rev` when the cached metadata and the
    /// persisted document carry them; chains compose over exactly that pair.
    pub(crate) identity: Option<String>,
    pub(crate) candidates: Vec<ChainCandidateModel>,
    pub(crate) grounded: Vec<crate::app::ExploitChainDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainCandidateModel {
    pub(crate) surface: String,
    pub(crate) links: Vec<ChainLinkModel>,
    pub(crate) rationale: String,
    /// Advisory chain-triage note: which constituents this chain would raise.
    pub(crate) mutation_note: Option<String>,
    /// The prompt draft Enter loads — navigate back to the entry finding.
    pub(crate) open_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainLinkModel {
    pub(crate) role: String,
    pub(crate) reference: String,
    pub(crate) severity: String,
    pub(crate) title: String,
    pub(crate) file: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProvePhaseModel {
    pub(crate) pending_result: Option<PhaseResultCardModel>,
    pub(crate) finding: Option<FindingDetailModel>,
    pub(crate) attack_path: TaintFlowPath,
    pub(crate) proof: Option<ProofReplayModel>,
    pub(crate) selection_disclosure: Option<SelectionDisclosureModel>,
    pub(crate) empty_hint: Option<String>,
    /// The bounded investigation plan card opened by `v`: what the verifier
    /// will pursue, under which safety boundary, and the exact command Enter
    /// drafts. Present only while the operator has the card open.
    pub(crate) investigation: Option<InvestigationPlanModel>,
    /// The Trace screen (`t`): where does this value travel. Original
    /// recorded path beside the operator-requested expansion from the
    /// durable static-evidence store.
    pub(crate) trace: Option<TraceEvidenceModel>,
    /// The operator's durable decision to postpone proof for exactly this
    /// finding generation. A decision, never evidence: it is disclosed beside
    /// the status and never moves proof confidence or the ladder.
    pub(crate) deferral: Option<kuzushi_core::workflow_attempts::ProofDeferralView>,
}

/// The data-flow evidence graph for one finding. The original path is what
/// discovery recorded (finding-keyed taint flow, else the evidence anchors);
/// the expanded path is every hop a `trace:expand` run appended with
/// "requested by operator" provenance. Open questions and evidence deltas
/// are the last expansion's advisory copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TraceEvidenceModel {
    pub(crate) last_outcome: Option<String>,
    pub(crate) reference: String,
    pub(crate) severity: String,
    /// `target …@rev · threat model @rev` when the cached metadata and the
    /// persisted document carry them.
    pub(crate) identity: Option<String>,
    pub(crate) original: Vec<TraceHopModel>,
    pub(crate) expanded: Vec<TraceHopModel>,
    pub(crate) open_questions: Vec<String>,
    pub(crate) evidence_deltas: Vec<String>,
    /// The exact command Enter loads — nothing runs from the screen.
    pub(crate) expand_command: String,
    pub(crate) next_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TraceHopModel {
    pub(crate) label: String,
    pub(crate) location: String,
    pub(crate) annotation: String,
}

/// The recommend-then-authorize card for a single-finding investigation.
/// Every field states something real: evidence goals derive from the
/// finding's recorded gaps, the boundary maps onto `verify:finding mode`,
/// and `command` is exactly what Enter loads into the prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InvestigationPlanModel {
    pub(crate) reference: String,
    pub(crate) severity: String,
    pub(crate) why: String,
    pub(crate) evidence_goals: Vec<String>,
    pub(crate) empirical: bool,
    pub(crate) local_readiness:
        Option<kuzushi_core::verification::application::LocalVerificationReadiness>,
    /// Configured verification models, with the panel first for preflight.
    /// Kept consistent with `command` and the selected config by construction.
    pub(crate) model_ladder: Vec<String>,
    pub(crate) command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelectionDisclosureModel {
    pub(crate) message: String,
    pub(crate) filter: Option<String>,
    pub(crate) reveal_command: String,
    pub(crate) reveal_label: &'static str,
}

/// Verification evidence for the selected projected finding. `replay_run_id`
/// is populated only when the finding points to a run with an actual on-disk
/// trace file; a persisted verification without that artifact is still proof,
/// but must not be labelled as a replay by the renderer.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProofReplayModel {
    pub(crate) finding_alias: Option<String>,
    pub(crate) proof_level: u8,
    pub(crate) verdict: String,
    pub(crate) backend: String,
    pub(crate) language: Option<String>,
    pub(crate) harness_path: Option<String>,
    pub(crate) crash_evidence: Option<String>,
    pub(crate) duration_ms: u64,
    pub(crate) cost_usd: f64,
    pub(crate) notes: Vec<String>,
    /// Parsed verification stage ladder (gate / panel / tie-break escalation),
    /// when one of the notes is a durable stage note. Drives the Prove card's
    /// tone-classified stage disclosure without discarding the raw notes.
    pub(crate) stages: Option<kuzushi_core::VerificationStageDisclosure>,
    pub(crate) created_at: String,
    pub(crate) provenance_run_id: Option<String>,
    pub(crate) replay_run_id: Option<String>,
    pub(crate) requires_revalidation: bool,
}

impl ProofReplayModel {
    pub(crate) fn has_replay(&self) -> bool {
        self.replay_run_id.is_some()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FixPhaseModel {
    pub(crate) findings: FindingsModel,
    pub(crate) review: ReviewQueueModel,
    pub(crate) attack_tree: AttackTree,
    pub(crate) dfd: DfdModel,
    pub(crate) finding: Option<FindingDetailModel>,
    pub(crate) selection_disclosure: Option<SelectionDisclosureModel>,
    pub(crate) patch: Option<PatchReviewModel>,
    pub(crate) remediation: RemediationLifecycleModel,
    pub(crate) threat_patch: Option<ThreatPatchCardModel>,
    pub(crate) report: ReportPreviewModel,
    pub(crate) export_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemediationLifecycleStage {
    NotDrafted,
    DraftAvailable,
    StagedForApproval,
    Applying,
    ApplyFailed,
    Applied,
    ReverifyRunning,
    Verified,
    StillVulnerable,
    NotRediscovered,
    Inconclusive,
    Failed,
    Interrupted,
    ChangedSinceApply,
    PriorFindingGeneration,
}

impl RemediationLifecycleStage {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NotDrafted => "Not drafted",
            Self::DraftAvailable => "Draft available · not applied",
            Self::StagedForApproval => "Staged for approval",
            Self::Applying => "Application pending · recovery state preserved",
            Self::ApplyFailed => "Application failed · patch not accepted",
            Self::Applied => "Applied · re-verification required",
            Self::ReverifyRunning => "Re-verification running",
            Self::Verified => "Verified",
            Self::StillVulnerable => "Still vulnerable",
            Self::NotRediscovered => "Not rediscovered",
            Self::Inconclusive => "Inconclusive",
            Self::Failed => "Re-verification failed",
            Self::Interrupted => "Re-verification interrupted",
            Self::ChangedSinceApply => "Changed since apply",
            Self::PriorFindingGeneration => "Receipt belongs to a prior finding observation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemediationLifecycleModel {
    pub(crate) load_state: RemediationLoadState,
    pub(crate) stage: RemediationLifecycleStage,
    pub(crate) application_id: Option<String>,
    pub(crate) patch_run_id: Option<String>,
    pub(crate) diff_hash: Option<String>,
    pub(crate) touched_paths: Vec<String>,
    pub(crate) reverify_run_id: Option<String>,
    pub(crate) detail: Option<String>,
    pub(crate) updated_at: Option<String>,
    pub(crate) reverify_command: Option<String>,
    pub(crate) reverify_control_hint: Option<String>,
    pub(crate) load_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemediationLoadState {
    Loading,
    Missing,
    Ready,
    Failed,
}

#[cfg(test)]
pub(crate) fn phase_cockpit_model(app: &ShellApp) -> Option<PhaseCockpitModel> {
    let journey = journey_model(app);
    let phase = phase_for_cockpit(app, journey.as_ref())?;
    Some(phase_cockpit_model_for_phase_with_journey(
        app,
        phase,
        journey.as_ref(),
    ))
}

pub(crate) fn phase_cockpit_model_for_phase(
    app: &ShellApp,
    phase: WorkflowPhase,
) -> PhaseCockpitModel {
    let journey = journey_model(app);
    phase_cockpit_model_for_phase_with_journey(app, phase, journey.as_ref())
}

pub(super) fn phase_cockpit_model_for_phase_with_journey(
    app: &ShellApp,
    phase: WorkflowPhase,
    journey: Option<&JourneyModel>,
) -> PhaseCockpitModel {
    let mut header = engagement_header_model(app, phase, journey);
    let result = header
        .result_card
        .as_ref()
        .filter(|card| card.has_result_actions());
    let body = phase_body(app, phase, result);
    scan::study::apply_header(&body, &mut header);
    PhaseCockpitModel {
        phase,
        header,
        body,
    }
}

#[cfg(test)]
fn phase_for_cockpit(app: &ShellApp, journey: Option<&JourneyModel>) -> Option<WorkflowPhase> {
    if app.shell_view() == ShellView::Activity {
        return app.activity().and_then(|activity| activity.origin_phase);
    }
    journey.map(|journey| journey.current)
}

fn engagement_header_model(
    app: &ShellApp,
    phase: WorkflowPhase,
    journey: Option<&JourneyModel>,
) -> EngagementHeaderModel {
    let context = context_strip_model(app);
    let context_state = context.context_state_segment();
    let guidance = phase_guidance(journey);
    let model = if app.shell_view() == ShellView::Activity {
        super::activity_execution_model_label(app)
            .unwrap_or_else(|| configured_model_label(&context.model))
    } else {
        configured_model_label(&context.model)
    };
    let result_card = phase_result_card(app, phase);
    let result_next = app
        .engagement
        .unresolved_phase_attempt(phase)
        .filter(|_| !app.prove_detail_owns_controls())
        .map(|record| super::journey::unresolved_attempt_action(app, record));
    EngagementHeaderModel {
        phase,
        reality_phase: guidance.reality_phase,
        checkpoint_drift: journey.and_then(|journey| journey.checkpoint_drift.clone()),
        target: context.target,
        context: context_state,
        model,
        threat_model: (phase == WorkflowPhase::Map)
            .then(|| super::threat_model_picker(app).header_chip())
            .flatten(),
        module: active_module_label(app),
        cost: app.session().session_cost_report(),
        cost_invalid: app.session().cost_accounting_error().is_some(),
        budget_usd: app.session().session_budget_usd(),
        liveness: super::work_liveness(app),
        finding_filter: super::findings::scope_filter::display(app),
        phase_rail: guidance.phase_rail,
        next_action: result_next.unwrap_or(guidance.next_action),
        next_tools: result_card
            .as_ref()
            .map_or(guidance.next_tools, |_| String::new()),
        result_card,
    }
}

fn phase_result_card(app: &ShellApp, phase: WorkflowPhase) -> Option<PhaseResultCardModel> {
    if app.prove_detail_owns_controls() {
        return None;
    }
    let presentation = app.phase_result_presentation(phase)?;
    Some(phase_result_card_model(app, phase, presentation))
}

fn phase_result_card_model(
    app: &ShellApp,
    phase: WorkflowPhase,
    presentation: crate::app::PhaseResultPresentation,
) -> PhaseResultCardModel {
    if let Some(review) = app
        .engagement
        .pending_phase_rerun()
        .filter(|review| review.phase == phase)
    {
        return phase_rerun_review_card(app, review);
    }
    let verified_remediation = app.verified_remediation_result_is_open(phase);
    // The strip renders `recommended` as its own trailing `next:` row, so
    // the identical row inside the presentation details would print twice.
    let trailing_next = format!("next: {}", presentation.recommended_next);
    let detail_rows = presentation
        .detail_rows
        .into_iter()
        .filter(|row| row.text != trailing_next)
        .collect();
    PhaseResultCardModel {
        attempt_id: presentation.attempt_id,
        outcome: presentation.outcome.clone(),
        emphasis: presentation.emphasis,
        compact_summary: compact_result_summary(&presentation.compact_summary),
        detail: presentation.detail_lines.join("\n"),
        detail_rows,
        semantic_keys: presentation.semantic_keys,
        control_hint: phase_result_control_hint(
            app,
            &presentation.actions,
            phase,
            &presentation.outcome,
            verified_remediation,
        ),
        actions: presentation.actions,
        recommended: presentation.recommended_next,
    }
}

fn phase_rerun_review_card(
    app: &ShellApp,
    review: &crate::app::PhaseRerunReview,
) -> PhaseResultCardModel {
    let detail_rows = if review.option_editor_open {
        phase_rerun_editor_rows(app, review)
    } else {
        phase_rerun_review_rows(review)
    };
    let detail = detail_rows
        .iter()
        .map(|row| row.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    PhaseResultCardModel {
        attempt_id: review.parent_attempt_id.clone(),
        outcome: format!("{} review", phase_rerun_action_label(review.derivation)),
        emphasis: crate::PhaseResultEmphasis::DominantDecision,
        compact_summary: format!("{} rerun review", review.phase.title()),
        detail,
        detail_rows,
        semantic_keys: std::collections::BTreeSet::new(),
        actions: Vec::new(),
        control_hint: phase_rerun_control_hint(review),
        recommended: if review.draft_modified {
            "review the draft changes; the saved run input remains unchanged".to_string()
        } else {
            "review the saved settings; the historical run remains unchanged".to_string()
        },
    }
}

fn phase_rerun_control_hint(review: &crate::app::PhaseRerunReview) -> String {
    if review.option_edit.is_some() {
        return "type primitive value · Enter save · Esc cancel edit".to_string();
    }
    if review.option_editor_open {
        return "j/k move · Space cycle yes/no or choice · Enter edit · Esc review".to_string();
    }
    "Enter dispatch draft · e edit rerun options · Esc cancel".to_string()
}

fn phase_rerun_editor_rows(
    app: &ShellApp,
    review: &crate::app::PhaseRerunReview,
) -> Vec<crate::app::PhaseResultDetailRow> {
    let mut rows = vec![phase_rerun_detail_row(format!(
        "{} · rerun draft options",
        review.tool
    ))];
    if let Some(descriptor) = app.registry().resolve_tool(&review.tool) {
        rows.extend(
            descriptor
                .options
                .iter()
                .filter(|spec| crate::app::option_is_operator_editable(spec))
                .enumerate()
                .map(|(index, spec)| {
                    let marker = if index == review.option_cursor {
                        ">"
                    } else {
                        " "
                    };
                    let value = review
                        .option_edit
                        .as_ref()
                        .filter(|edit| edit.option_name == spec.name)
                        .map(|edit| edit.draft.clone())
                        .or_else(|| {
                            review
                                .prepared_input
                                .get(&spec.name)
                                .map(crate::app::format_option_value)
                        })
                        .unwrap_or_else(|| "unset".to_string());
                    phase_rerun_detail_row(format!(
                        "{marker} {} = {value} · {}",
                        crate::ui_view_models::option_display_name(&spec.name),
                        spec.description
                    ))
                }),
        );
    }
    // The editor is where the operator remedies a refused dispatch, so the
    // reason has to stay on screen while they do it.
    push_phase_rerun_dispatch_refusal(&mut rows, review);
    if let Some(error) = review.option_error.as_deref() {
        rows.push(phase_rerun_detail_row(format!("REFUSED · INPUT · {error}")));
    }
    rows
}

fn compact_result_summary(summary: &crate::PhaseResultCompactSummary) -> String {
    let mut parts = vec![format!("{} ready", summary.phase.title())];
    if !summary.receipt_recorded {
        parts.push("⚠ receipt unavailable".to_string());
    }
    if let Some(cost) = summary.cost.as_deref() {
        parts.push(if cost_needs_warning(cost) {
            format!("⚠ {cost}")
        } else {
            cost.to_string()
        });
    }
    if !summary.revision_recorded {
        parts.push("⚠ rev unrecorded".to_string());
    }
    parts.extend([
        format!("{} run(s)", summary.run_count),
        format!("receipt links {}", summary.artifact_count),
    ]);
    parts.extend(summary.findings_segment());
    parts.join(" · ")
}

fn cost_needs_warning(cost: &str) -> bool {
    let normalized = cost.to_ascii_lowercase();
    [
        "incomplete",
        "unavailable",
        "invalid",
        "not recorded",
        "accounting",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn phase_rerun_review_rows(
    review: &crate::app::PhaseRerunReview,
) -> Vec<crate::app::PhaseResultDetailRow> {
    let mut rows = vec![phase_rerun_detail_row(format!(
        "{} · {}",
        review.tool, review.tool_description
    ))];
    if review.changed_options.is_empty() {
        rows.push(phase_rerun_detail_row(
            "Options · descriptor defaults".to_string(),
        ));
    } else {
        rows.extend(review.changed_options.iter().map(|option| {
            phase_rerun_detail_row(format!(
                "{} = {} · {}",
                option.label, option.value, option.description
            ))
        }));
    }
    push_phase_rerun_dispatch_refusal(&mut rows, review);
    rows
}

fn push_phase_rerun_dispatch_refusal(
    rows: &mut Vec<crate::app::PhaseResultDetailRow>,
    review: &crate::app::PhaseRerunReview,
) {
    if let Some(error) = review.dispatch_error.as_deref() {
        rows.push(phase_rerun_detail_row(format!(
            "REFUSED · DISPATCH · {error}"
        )));
    }
}

fn phase_rerun_detail_row(text: String) -> crate::app::PhaseResultDetailRow {
    crate::app::PhaseResultDetailRow {
        key: None,
        disclosed_keys: std::collections::BTreeSet::new(),
        text,
    }
}

fn phase_rerun_action_label(
    derivation: Option<kuzushi_core::workflow_attempts::PhaseAttemptDerivation>,
) -> &'static str {
    match derivation {
        Some(kuzushi_core::workflow_attempts::PhaseAttemptDerivation::Refine) => "refine",
        Some(kuzushi_core::workflow_attempts::PhaseAttemptDerivation::Regenerate) => "regenerate",
        _ => "run again",
    }
}

fn phase_result_control_hint(
    app: &ShellApp,
    actions: &[kuzushi_core::workflow_attempts::PhaseResultAction],
    phase: WorkflowPhase,
    outcome: &str,
    verified_remediation: bool,
) -> String {
    if app.phase_result_keys_are_available() {
        return result_action_labels_for(app, actions, phase, outcome, verified_remediation);
    }
    if app.input_mode() == InputMode::Navigate && !app.input().is_empty() {
        return navigation_draft_result_hint(app);
    }
    prompt_result_control_hint(app)
}

fn navigation_draft_result_hint(app: &ShellApp) -> String {
    let bindings = app
        .ui()
        .keymap_binding_labels("composer", "prompt_mode", &["Esc"]);
    if bindings.is_empty() {
        return "Prompt unbound · configure composer.prompt_mode".to_string();
    }
    format!("{} prompt to finish or clear the draft", bindings.join("/"))
}

pub(super) fn prompt_result_control_hint(app: &ShellApp) -> String {
    let bindings = app
        .ui()
        .keymap_binding_labels("composer", "navigate_mode", &["Esc"]);
    if bindings.is_empty() {
        return "Navigate unbound · configure composer.navigate_mode".to_string();
    }
    let binding = bindings.join("/");
    if app.input().is_empty() {
        format!("{binding} Navigate to resolve this result")
    } else {
        format!("{binding} Navigate after finishing or clearing prompt draft")
    }
}

#[cfg(test)]
fn result_action_labels(phase: WorkflowPhase, outcome: &str) -> String {
    let app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let actions = fallback_result_policy(phase, outcome).actions;
    result_action_labels_for(&app, &actions, phase, outcome, false)
}

#[cfg(test)]
fn fallback_result_policy(phase: WorkflowPhase, outcome: &str) -> crate::app::PhaseResultPolicy {
    phase_result_policy(
        Some(phase),
        phase_attempt_outcome_from_label(outcome),
        false,
    )
}

fn configured_model_label(model: &str) -> String {
    if model == "unconfigured" {
        model.to_string()
    } else {
        format!("configured {model}")
    }
}

struct PhaseGuidance {
    reality_phase: Option<WorkflowPhase>,
    phase_rail: Vec<JourneyPhaseStatus>,
    next_action: String,
    next_tools: String,
}

fn phase_guidance(journey: Option<&JourneyModel>) -> PhaseGuidance {
    match journey {
        Some(journey) => PhaseGuidance {
            reality_phase: Some(journey.current),
            phase_rail: journey.phases.clone(),
            // Page navigation changes the composition, not workspace reality.
            // `next` must always describe what it will actually do from the
            // current engagement phase, even while the operator inspects a
            // past or future page.
            next_action: journey.next_action.clone(),
            next_tools: journey.next_tools.clone(),
        },
        None => PhaseGuidance {
            reality_phase: None,
            phase_rail: Vec::new(),
            next_action: "select a target to begin the engagement".to_string(),
            next_tools: "target <path>".to_string(),
        },
    }
}

fn active_module_label(app: &ShellApp) -> String {
    app.running_tool_name()
        .or_else(|| app.focused_module())
        .unwrap_or("all modules")
        .to_string()
}

fn phase_body(
    app: &ShellApp,
    phase: WorkflowPhase,
    pending_result: Option<&PhaseResultCardModel>,
) -> PhaseCockpitBody {
    match phase {
        WorkflowPhase::Map => PhaseCockpitBody::Map(map_phase_model(app)),
        WorkflowPhase::Scan => PhaseCockpitBody::Scan(scan_phase_model(app)),
        WorkflowPhase::Review => PhaseCockpitBody::Review(review_phase_model(app)),
        WorkflowPhase::Prove => {
            PhaseCockpitBody::Prove(prove_phase_model(app, pending_result.cloned()))
        }
        WorkflowPhase::Fix => PhaseCockpitBody::Fix(fix_phase_model(app)),
    }
}

#[cfg(test)]
mod tests;
