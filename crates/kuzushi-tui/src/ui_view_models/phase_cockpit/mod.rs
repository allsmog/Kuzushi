//! Real-data presentation models for the five durable cockpit phase pages.
//!
//! These DTOs project persisted artifacts, findings, and application state.
//! They do not infer progress, proof, application, or remediation truth that
//! Kuzushi has not actually observed.

use super::{
    context_strip_model, journey_model, AttackSurfaceRiskModel, AttackTree, ContextSnapshotModel,
    DfdModel, FindingDetailModel, FindingsModel, JourneyModel, JourneyPhaseStatus,
    PatchReviewModel, ProjectModel, ReportPreviewModel, ReviewQueueModel, RiskByModule,
    TaintFlowPath, ThreatPatchCardModel,
};
#[cfg(test)]
use crate::{phase_attempt_outcome_from_label, phase_result_policy};
use crate::{InputMode, PhaseResultCommand, ShellApp, ShellView};
use kuzushi_core::WorkflowPhase;

mod confirm;
mod layout;
#[cfg(test)]
mod layout_matrix_tests;
mod map;
mod phase_bodies;
mod scan;

use confirm::prove_phase_model;
pub(crate) use layout::{
    phase_presentation_plan, phase_surface_specs, AttentionMode, LayoutDensity,
    PhasePresentationPlan, PhaseSurfaceId, PlannedPhaseSurface, SurfaceInteraction, SurfaceState,
};
use map::map_phase_model;
use phase_bodies::{fix_phase_model, review_phase_model};
use scan::scan_phase_model;

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
    pub(crate) detail: String,
    pub(crate) actions: Vec<kuzushi_core::workflow_attempts::PhaseResultAction>,
    pub(crate) control_hint: String,
    pub(crate) recommended: String,
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
    pub(crate) scope: String,
    pub(crate) plan: String,
    pub(crate) attempt: Option<ScanAttemptModel>,
    pub(crate) engine_outcomes: Vec<ScanEngineOutcomeModel>,
    pub(crate) empty_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScanAttemptModel {
    pub(crate) attempt_id: Option<String>,
    pub(crate) run_id: String,
    pub(crate) run_refs: Vec<String>,
    pub(crate) outcome: String,
    pub(crate) disposition: String,
    pub(crate) freshness: String,
    pub(crate) findings: Option<u64>,
    pub(crate) findings_added: Option<u64>,
    pub(crate) findings_updated: Option<u64>,
    pub(crate) artifact_count: usize,
    pub(crate) artifact_paths: Vec<String>,
    pub(crate) duration_secs: Option<u64>,
    pub(crate) cost_usd: Option<f64>,
    pub(crate) cost_complete: Option<bool>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanEngineOutcomeModel {
    pub(crate) engine: String,
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
    pub(crate) target: String,
    pub(crate) context: String,
    pub(crate) model: String,
    pub(crate) module: String,
    pub(crate) cost_usd: f64,
    pub(crate) cost_complete: bool,
    pub(crate) cost_invalid: bool,
    pub(crate) budget_usd: Option<f64>,
    pub(crate) live: bool,
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
    pub(crate) dfd: DfdModel,
    pub(crate) empty_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReviewPhaseModel {
    pub(crate) review: ReviewQueueModel,
    pub(crate) finding: Option<FindingDetailModel>,
    pub(crate) selection_disclosure: Option<SelectionDisclosureModel>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProvePhaseModel {
    pub(crate) finding: Option<FindingDetailModel>,
    pub(crate) attack_path: TaintFlowPath,
    pub(crate) proof: Option<ProofReplayModel>,
    pub(crate) selection_disclosure: Option<SelectionDisclosureModel>,
    pub(crate) empty_hint: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelectionDisclosureModel {
    pub(crate) message: String,
    pub(crate) filter: String,
    pub(crate) reveal_command: &'static str,
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
    PhaseCockpitModel {
        phase,
        header: engagement_header_model(app, phase, journey),
        body: phase_body(app, phase),
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
    EngagementHeaderModel {
        phase,
        reality_phase: guidance.reality_phase,
        target: context.target,
        context: context_state,
        model,
        module: active_module_label(app),
        cost_usd: app.session().session_cost_usd(),
        cost_complete: app.session().cost_accounting_is_complete(),
        cost_invalid: app.session().cost_accounting_error().is_some(),
        budget_usd: app.session().session_budget_usd(),
        live: app.has_running_work(),
        finding_filter: app.active_findings_filter().clone(),
        phase_rail: guidance.phase_rail,
        next_action: guidance.next_action,
        next_tools: guidance.next_tools,
        result_card: phase_result_card(app, phase),
    }
}

fn phase_result_card(app: &ShellApp, phase: WorkflowPhase) -> Option<PhaseResultCardModel> {
    let record = app.engagement.unresolved_phase_attempt(phase)?;
    let live_receipt = app
        .activity()
        .and_then(|session| session.run_focus_receipt.as_ref())
        .filter(|receipt| receipt.attempt_id.as_deref() == Some(&record.completed.attempt_id));
    let outcome = format!("{:?}", record.completed.outcome).to_ascii_lowercase();
    let detail = result_receipt_detail(&record.completed, live_receipt, &outcome);
    let policy = app.projected_phase_result_policy(phase)?;
    let actions =
        crate::app::ordered_phase_result_actions(phase, record.completed.outcome, &policy.actions);
    let verified_remediation = app.verified_remediation_result_is_open(phase);
    let recommended = policy
        .recommended_next
        .unwrap_or_else(|| "open the result and choose a disposition".to_string());
    Some(PhaseResultCardModel {
        attempt_id: record.completed.attempt_id.clone(),
        outcome: outcome.clone(),
        detail,
        control_hint: phase_result_control_hint(
            app,
            &actions,
            phase,
            &outcome,
            verified_remediation,
        ),
        actions,
        recommended,
    })
}

fn phase_result_control_hint(
    app: &ShellApp,
    actions: &[kuzushi_core::workflow_attempts::PhaseResultAction],
    phase: WorkflowPhase,
    outcome: &str,
    verified_remediation: bool,
) -> String {
    if app.input_mode() == InputMode::Navigate {
        return result_action_labels_for(app, actions, phase, outcome, verified_remediation);
    }
    prompt_result_control_hint(app)
}

fn prompt_result_control_hint(app: &ShellApp) -> String {
    let bindings = app
        .ui()
        .keymap_binding_labels("composer", "navigate_mode", &["F2"]);
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

fn result_receipt_detail(
    completed: &kuzushi_core::workflow_attempts::PhaseAttemptCompleted,
    live: Option<&crate::app::RunFocusReceipt>,
    outcome: &str,
) -> String {
    if let Some(receipt) = live {
        return format!(
            "{} · {} finding delta · {} artifact delta · {} interaction(s)",
            receipt.summary(),
            receipt.changed_findings,
            receipt.changed_artifacts.len(),
            receipt.interaction_count
        );
    }
    let Some(receipt) = completed.receipt.as_ref() else {
        return format!(
            "{} canonical run reference(s) · legacy receipt metadata unavailable",
            completed.run_refs.len()
        );
    };
    format!(
        "{outcome} · {} run{} · {}s · {} · {} finding delta · {} artifact delta · {} interaction(s)",
        receipt.run_count,
        if receipt.run_count == 1 { "" } else { "s" },
        receipt.elapsed_secs,
        receipt.cost,
        receipt.changed_findings,
        receipt.changed_artifacts.len(),
        receipt.interaction_count
    )
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

fn result_action_labels_for(
    app: &ShellApp,
    actions: &[kuzushi_core::workflow_attempts::PhaseResultAction],
    phase: WorkflowPhase,
    outcome: &str,
    verified_remediation: bool,
) -> String {
    actions
        .iter()
        .map(|action| result_action_label(app, *action, phase, outcome, verified_remediation))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn result_action_label(
    app: &ShellApp,
    action: kuzushi_core::workflow_attempts::PhaseResultAction,
    phase: WorkflowPhase,
    outcome: &str,
    verified_remediation: bool,
) -> String {
    use kuzushi_core::workflow_attempts::PhaseResultAction::*;
    let verb = match action {
        Select if outcome == "partial" => "Acknowledge & use partial".to_string(),
        Select if verified_remediation => "Acknowledge verified".to_string(),
        Select => select_action_label(phase).to_string(),
        SelectAndContinue => continue_action_label(phase).to_string(),
        SelectAndReport => "Use & Report".to_string(),
        Open => "Open".to_string(),
        Refine => "Refine".to_string(),
        RunAgain => "Run again".to_string(),
        Regenerate => "Regenerate".to_string(),
        Discard if matches!(phase, WorkflowPhase::Review | WorkflowPhase::Fix) => {
            "Discard".to_string()
        }
        Discard => "Dismiss".to_string(),
    };
    let command = PhaseResultCommand::from_action(action);
    let labels = app.ui().keymap_binding_labels(
        "phase_result",
        command.action_id(),
        &[command.default_hint()],
    );
    if labels.is_empty() {
        format!("unbound {verb}")
    } else {
        format!("{} {verb}", labels.join("/"))
    }
}

fn select_action_label(phase: WorkflowPhase) -> &'static str {
    match phase {
        WorkflowPhase::Map => "Use map",
        WorkflowPhase::Scan => "Use scan",
        WorkflowPhase::Review => "Commit decisions",
        WorkflowPhase::Prove => "Use proof set",
        WorkflowPhase::Fix => "Select patch",
    }
}

fn continue_action_label(phase: WorkflowPhase) -> &'static str {
    match phase {
        WorkflowPhase::Map => "Use & Scan",
        WorkflowPhase::Scan => "Use & Review",
        WorkflowPhase::Review => "Commit & Prove",
        WorkflowPhase::Prove => "Use & Fix",
        WorkflowPhase::Fix => "Continue",
    }
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

fn phase_body(app: &ShellApp, phase: WorkflowPhase) -> PhaseCockpitBody {
    match phase {
        WorkflowPhase::Map => PhaseCockpitBody::Map(map_phase_model(app)),
        WorkflowPhase::Scan => PhaseCockpitBody::Scan(scan_phase_model(app)),
        WorkflowPhase::Review => PhaseCockpitBody::Review(review_phase_model(app)),
        WorkflowPhase::Prove => PhaseCockpitBody::Prove(prove_phase_model(app)),
        WorkflowPhase::Fix => PhaseCockpitBody::Fix(fix_phase_model(app)),
    }
}

#[cfg(test)]
mod tests;
