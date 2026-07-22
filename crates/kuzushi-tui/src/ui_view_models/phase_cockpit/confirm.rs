use super::{InvestigationPlanModel, ProofReplayModel, ProvePhaseModel};
use crate::ui_view_models::{
    current_finding_for_detail, finding_detail_model_for_projection, findings_model,
    taint_flow_path_for_finding,
};
use crate::{ShellApp, ViewDataState};
use kuzushi_core::{PersistedVerification, RunArtifactRead};

pub(super) fn prove_phase_model(app: &ShellApp) -> ProvePhaseModel {
    let findings = findings_model(app);
    let selected = current_finding_for_detail(app);
    let finding = selected
        .as_ref()
        .map(|(alias, finding)| finding_detail_model_for_projection(app, alias.clone(), finding));
    let proof = selected.as_ref().and_then(|(alias, finding)| {
        finding.verification.as_ref().map(|verification| {
            proof_replay_model(app, alias.clone(), finding.scan_id.as_deref(), verification)
        })
    });
    let investigation =
        investigation_plan_model(app, selected.as_ref(), finding.as_ref(), proof.as_ref());
    ProvePhaseModel {
        selection_disclosure: super::phase_bodies::actionable_selection_disclosure(
            app,
            &findings,
            finding.as_ref(),
        ),
        finding,
        attack_path: taint_flow_path_for_finding(
            app,
            selected.as_ref().map(|(_, finding)| finding),
        ),
        proof,
        empty_hint: selected
            .is_none()
            .then_some("select a finding to inspect its path and proof"),
        investigation,
    }
}

/// The bounded investigation plan card. Built only while the operator holds
/// the draft open AND a finding is selected; the command it previews is
/// exactly what Enter loads into the prompt — nothing runs from the card.
fn investigation_plan_model(
    app: &ShellApp,
    selected: Option<&(Option<String>, kuzushi_core::Finding)>,
    detail: Option<&crate::ui_view_models::FindingDetailModel>,
    proof: Option<&ProofReplayModel>,
) -> Option<InvestigationPlanModel> {
    let boundary = app.router.workbench().investigation_draft()?;
    let (alias, raw) = selected?;
    let detail = detail?;
    let command = format!(
        "run verify:finding {}",
        serde_json::json!({ "fingerprint": raw.fingerprint, "mode": boundary.mode_value() })
    );
    Some(InvestigationPlanModel {
        reference: alias
            .clone()
            .unwrap_or_else(|| detail.identity_label.clone()),
        severity: detail.severity_label.clone(),
        why: format!(
            "evidence {} · proof {} — the claims below stay unproven until an investigation records them",
            detail.evidence_state, detail.proof_confidence_label
        ),
        evidence_goals: investigation_evidence_goals(raw, proof),
        empirical: boundary == crate::app::InvestigationBoundary::LocalReproduction,
        command,
    })
}

/// Evidence goals derive from the finding's recorded gaps, so the card only
/// promises work this finding actually needs.
fn investigation_evidence_goals(
    finding: &kuzushi_core::Finding,
    proof: Option<&ProofReplayModel>,
) -> Vec<String> {
    let mut goals = Vec::new();
    if finding.evidence.is_empty() {
        goals.push("Recover structured evidence anchors (source and sink lines)".to_string());
    }
    if finding.corroboration_count <= 1 && finding.sources.len() <= 1 {
        goals.push("Corroborate the signal through an independent source".to_string());
    }
    match proof {
        None => {
            goals.push("Attempt safe reproduction and record a runtime witness".to_string());
        }
        Some(replay) if replay.requires_revalidation => {
            goals.push("Re-validate the stale proof against the current observation".to_string());
        }
        Some(_) => {}
    }
    goals.push("Record the verifier verdict and rationale as durable evidence".to_string());
    goals
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
        requires_revalidation: !verification.is_current_for_scan(current_scan_id),
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

#[cfg(test)]
mod investigation_goal_tests {
    use super::*;
    use kuzushi_core::{Finding, Severity};

    fn bare_finding() -> Finding {
        Finding::new_semgrep(
            "demo.goal",
            "src/lib.rs",
            7,
            Some(3),
            Severity::High,
            "goal",
        )
    }

    fn replay(requires_revalidation: bool) -> ProofReplayModel {
        ProofReplayModel {
            finding_alias: None,
            proof_level: 2,
            verdict: "proven".to_string(),
            backend: "sandbox".to_string(),
            language: None,
            harness_path: None,
            crash_evidence: None,
            duration_ms: 10,
            cost_usd: 0.0,
            notes: Vec::new(),
            created_at: "now".to_string(),
            provenance_run_id: None,
            replay_run_id: None,
            requires_revalidation,
        }
    }

    #[test]
    fn unproven_uncorroborated_finding_derives_every_gap_as_a_goal() {
        let goals = investigation_evidence_goals(&bare_finding(), None);
        assert!(goals.iter().any(|goal| goal.contains("evidence anchors")));
        assert!(goals.iter().any(|goal| goal.contains("independent source")));
        assert!(goals.iter().any(|goal| goal.contains("runtime witness")));
        assert!(
            goals.last().unwrap().contains("durable evidence"),
            "{goals:?}"
        );
    }

    #[test]
    fn proven_finding_only_re_validates_when_the_proof_went_stale() {
        let fresh = investigation_evidence_goals(&bare_finding(), Some(&replay(false)));
        assert!(!fresh.iter().any(|goal| goal.contains("runtime witness")));
        assert!(!fresh.iter().any(|goal| goal.contains("stale proof")));

        let stale = investigation_evidence_goals(&bare_finding(), Some(&replay(true)));
        assert!(stale.iter().any(|goal| goal.contains("stale proof")));
    }
}
