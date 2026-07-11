use super::{ConfirmPhaseModel, ProofReplayModel};
use crate::ui_view_models::{
    current_finding_for_detail, selected_finding_detail_model, selected_taint_flow_path,
};
use crate::{ShellApp, ViewDataState};
use kuzushi_core::{PersistedVerification, RunArtifactRead};

pub(super) fn confirm_phase_model(app: &ShellApp) -> ConfirmPhaseModel {
    let selected = current_finding_for_detail(app);
    let proof = selected.as_ref().and_then(|(alias, finding)| {
        finding.verification.as_ref().map(|verification| {
            proof_replay_model(app, alias.clone(), finding.scan_id.as_deref(), verification)
        })
    });
    ConfirmPhaseModel {
        finding: selected_finding_detail_model(app),
        attack_path: selected_taint_flow_path(app),
        proof,
        empty_hint: selected
            .is_none()
            .then_some("select a finding to inspect its path and proof"),
    }
}

fn proof_replay_model(
    app: &ShellApp,
    finding_alias: Option<String>,
    current_scan_id: Option<&str>,
    verification: &PersistedVerification,
) -> ProofReplayModel {
    let provenance_run_id = verification
        .verification_run_id
        .as_deref()
        .filter(|run_id| !run_id.is_empty())
        .map(str::to_string);
    let replay_run_id = provenance_run_id
        .as_deref()
        .filter(|run_id| run_trace_exists(app, run_id))
        .map(str::to_string);
    ProofReplayModel {
        finding_alias,
        proof_level: verification.proof_level,
        verdict: verification.proof_verdict.as_str().to_string(),
        backend: verification.backend.as_str().to_string(),
        language: verification.language.clone(),
        harness_path: verification.harness_path.clone(),
        crash_evidence: verification.crash_evidence.clone(),
        duration_ms: verification.duration_ms,
        cost_usd: verification.cost_usd,
        notes: verification.notes.clone(),
        created_at: verification.created_at.clone(),
        provenance_run_id,
        replay_run_id,
        requires_revalidation: verification
            .verified_scan_id
            .as_deref()
            .zip(current_scan_id)
            .is_some_and(|(verified, current)| verified != current),
    }
}

fn run_trace_exists(app: &ShellApp, run_id: &str) -> bool {
    let Some(target) = app.target() else {
        return false;
    };
    matches!(
        app.workbench_cache()
            .borrow()
            .cached_run_artifact_text(target, run_id, "trace.jsonl"),
        ViewDataState::Ready(RunArtifactRead::Ready { value, .. }) if !value.is_empty()
    )
}
