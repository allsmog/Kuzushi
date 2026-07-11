//! Real-data presentation models for the four Atlas/PDF phase compositions.
//!
//! These DTOs deliberately compose existing Workbench and Activity models.
//! They do not infer progress, proof, or telemetry that Kuzushi has not
//! actually observed.

use super::{
    context_strip_model, journey_model, AttackTree, DfdModel, FindingDetailModel, FindingsHeatmap,
    FindingsModel, JourneyPhaseStatus, PatchReviewModel, ReportPreviewModel, ReviewQueueModel,
    SourceTreeModel, StrategyQueueModel, TaintFlowPath, ThreatPatchCardModel,
};
use crate::{ShellApp, ShellView};
use kuzushi_core::WorkflowPhase;

mod confirm;
mod map;
mod phase_bodies;

use confirm::confirm_phase_model;
use map::map_phase_model;
use phase_bodies::{fix_phase_model, hunt_phase_model};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PhaseCockpitModel {
    pub(crate) phase: WorkflowPhase,
    pub(crate) header: EngagementHeaderModel,
    pub(crate) body: PhaseCockpitBody,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PhaseCockpitBody {
    Map(MapPhaseModel),
    Hunt(HuntPhaseModel),
    Confirm(ConfirmPhaseModel),
    Fix(FixPhaseModel),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EngagementHeaderModel {
    /// Phase that owns this composition (captured from Activity when present).
    pub(crate) phase: WorkflowPhase,
    pub(crate) target: String,
    pub(crate) context: String,
    pub(crate) model: String,
    pub(crate) module: String,
    pub(crate) cost_usd: f64,
    pub(crate) budget_usd: Option<f64>,
    pub(crate) live: bool,
    pub(crate) phase_rail: Vec<JourneyPhaseStatus>,
    pub(crate) next_action: String,
    pub(crate) next_tools: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MapPhaseModel {
    pub(crate) run_id: Option<String>,
    pub(crate) elapsed_secs: Option<u64>,
    pub(crate) run_cost_usd: f64,
    pub(crate) task_counts: ActivityTaskCountModel,
    pub(crate) console: Vec<MapConsoleRow>,
    pub(crate) hidden_console_rows: usize,
    pub(crate) artifact_metrics: Vec<MapArtifactMetric>,
    pub(crate) empty_hint: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MapArtifactMetric {
    pub(crate) label: &'static str,
    pub(crate) value: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ActivityTaskCountModel {
    pub(crate) total: usize,
    pub(crate) queued: usize,
    pub(crate) active: usize,
    pub(crate) canceling: usize,
    pub(crate) completed: usize,
    pub(crate) failed: usize,
    pub(crate) blocked: usize,
    pub(crate) canceled: usize,
    pub(crate) skipped: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MapConsoleRow {
    pub(crate) sequence: usize,
    pub(crate) started_at_ms: Option<u64>,
    pub(crate) kind: String,
    pub(crate) label: String,
    pub(crate) module: Option<String>,
    pub(crate) verb: Option<String>,
    pub(crate) severity: Option<String>,
    pub(crate) latency_ms: Option<u64>,
    pub(crate) cost_usd: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HuntPhaseModel {
    pub(crate) source: SourceTreeModel,
    pub(crate) strategy: StrategyQueueModel,
    pub(crate) review: ReviewQueueModel,
    pub(crate) heatmap: FindingsHeatmap,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ConfirmPhaseModel {
    pub(crate) finding: Option<FindingDetailModel>,
    pub(crate) attack_path: TaintFlowPath,
    pub(crate) proof: Option<ProofReplayModel>,
    pub(crate) empty_hint: Option<&'static str>,
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
    pub(crate) patch: Option<PatchReviewModel>,
    pub(crate) threat_patch: Option<ThreatPatchCardModel>,
    pub(crate) report: ReportPreviewModel,
    pub(crate) export_command: String,
}

pub(crate) fn phase_cockpit_model(app: &ShellApp) -> Option<PhaseCockpitModel> {
    let phase = phase_for_cockpit(app)?;
    Some(phase_cockpit_model_for_phase(app, phase))
}

pub(crate) fn phase_cockpit_model_for_phase(
    app: &ShellApp,
    phase: WorkflowPhase,
) -> PhaseCockpitModel {
    PhaseCockpitModel {
        phase,
        header: engagement_header_model(app, phase),
        body: phase_body(app, phase),
    }
}

fn phase_for_cockpit(app: &ShellApp) -> Option<WorkflowPhase> {
    if app.shell_view() == ShellView::Activity {
        return app.activity().and_then(|activity| activity.origin_phase);
    }
    journey_model(app).map(|journey| journey.current)
}

fn engagement_header_model(app: &ShellApp, phase: WorkflowPhase) -> EngagementHeaderModel {
    let context = context_strip_model(app);
    let context_state = context.context_state_segment();
    let guidance = phase_guidance(app);
    EngagementHeaderModel {
        phase,
        target: context.target,
        context: context_state,
        model: context.model,
        module: active_module_label(app),
        cost_usd: app.session().session_cost_usd(),
        budget_usd: app.session().session_budget_usd(),
        live: app.has_running_work(),
        phase_rail: guidance.phase_rail,
        next_action: guidance.next_action,
        next_tools: guidance.next_tools,
    }
}

struct PhaseGuidance {
    phase_rail: Vec<JourneyPhaseStatus>,
    next_action: String,
    next_tools: String,
}

fn phase_guidance(app: &ShellApp) -> PhaseGuidance {
    match journey_model(app) {
        Some(journey) => PhaseGuidance {
            phase_rail: journey.phases,
            // Page navigation changes the composition, not workspace reality.
            // `next` must always describe what it will actually do from the
            // current engagement phase, even while the operator inspects a
            // past or future page.
            next_action: journey.next_action,
            next_tools: journey.next_tools,
        },
        None => PhaseGuidance {
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
        WorkflowPhase::Hunt => PhaseCockpitBody::Hunt(hunt_phase_model(app)),
        WorkflowPhase::Confirm => PhaseCockpitBody::Confirm(confirm_phase_model(app)),
        WorkflowPhase::Fix => PhaseCockpitBody::Fix(fix_phase_model(app)),
    }
}

#[cfg(test)]
mod tests;
