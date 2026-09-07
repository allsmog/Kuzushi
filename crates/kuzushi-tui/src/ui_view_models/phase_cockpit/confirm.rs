use super::trace_evidence::trace_evidence_model;
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
    let attack_path =
        taint_flow_path_for_finding(app, selected.as_ref().map(|(_, finding)| finding));
    let trace = trace_evidence_model(app, selected.as_ref(), finding.as_ref(), &attack_path);
    ProvePhaseModel {
        selection_disclosure: super::phase_bodies::actionable_selection_disclosure(
            app,
            &findings,
            finding.as_ref(),
        ),
        finding,
        attack_path,
        proof,
        empty_hint: selected.is_none().then(|| prove_empty_hint(app)),
        investigation,
        trace,
        deferral: selected_proof_deferral(app, selected.as_ref()),
    }
}

/// The durable proof deferral for the selected finding, if the operator
/// recorded one against this exact discovery generation.
fn selected_proof_deferral(
    app: &ShellApp,
    selected: Option<&(Option<String>, kuzushi_core::Finding)>,
) -> Option<kuzushi_core::workflow_attempts::ProofDeferralView> {
    let (_, finding) = selected?;
    app.engagement
        .proof_deferral_for(finding)
        .map(kuzushi_core::workflow_attempts::ProofDeferralView::from_record)
}

fn prove_empty_hint(app: &ShellApp) -> String {
    let Some(deferral) = app.engagement.latest_proof_deferral() else {
        return "select a finding to inspect its path and proof".to_string();
    };
    let view = kuzushi_core::workflow_attempts::ProofDeferralView::from_record(deferral);
    format!(
        "proof deferral recorded for {} by {} · {}. No proof was produced; open Review to select a finding",
        view.subject, view.actor, view.reason
    )
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
    Some(InvestigationPlanModel {
        reference: alias
            .clone()
            .unwrap_or_else(|| detail.identity_label.clone()),
        severity: detail.severity_label.clone(),
        why: format!(
            "evidence {} · proof {} — the claims below stay unproven until an investigation records them",
            detail.evidence_state, detail.proof_confidence_label
        ),
        evidence_goals: investigation_evidence_goals(raw, proof, boundary),
        empirical: boundary == crate::app::InvestigationBoundary::LocalReproduction,
        model_ladder: investigation_model_ladder(app),
        command: investigation_verify_command(app, &raw.fingerprint, boundary),
    })
}

/// Builds the exact `run verify:finding {…}` command the investigation card
/// previews. This is the single source of truth for that command: the Prove
/// card renders it and the Enter-to-draft key handler drafts it, so the
/// preview can never diverge from what actually runs. Operator-stored model
/// knobs (`model`, `gateModel`, verifier `passes`) are folded in so the
/// drafted command carries the same models the card's ladder discloses.
pub(crate) fn investigation_verify_command(
    app: &ShellApp,
    fingerprint: &str,
    boundary: crate::app::InvestigationBoundary,
) -> String {
    let mut input = serde_json::Map::new();
    input.insert("fingerprint".to_string(), serde_json::json!(fingerprint));
    input.insert("mode".to_string(), serde_json::json!(boundary.mode_value()));
    for (key, value) in stored_verify_model_knobs(app) {
        input.insert(key, value);
    }
    format!("run verify:finding {}", serde_json::Value::Object(input))
}

/// The operator-stored verify:finding model knobs, keyed canonically, that
/// belong in a drafted verification. Only knobs the operator actually set are
/// present, so an unconfigured engagement drafts just `fingerprint`/`mode`.
fn stored_verify_model_knobs(app: &ShellApp) -> serde_json::Map<String, serde_json::Value> {
    let stored = app.option_store().effective_stored_values("verify:finding");
    let mut knobs = serde_json::Map::new();
    for (canonical, aliases) in [
        ("model", &[] as &[&str]),
        ("gateModel", &["gate_model"]),
        ("escalationModel", &["escalation_model"]),
        ("VERIFY_PASSES", &["passes"]),
    ] {
        let value = stored
            .get(canonical)
            .or_else(|| aliases.iter().find_map(|alias| stored.get(*alias)));
        if let Some(value) = value {
            knobs.insert(canonical.to_string(), value.clone());
        }
    }
    knobs
}

/// A human-readable summary of which models the drafted verification will use,
/// in execution order: the cheap plausibility gate (rejection only), then the
/// full-strength panel. Both rows report exactly the models
/// `investigation_verify_command` folds into the drafted command.
fn investigation_model_ladder(app: &ShellApp) -> Vec<String> {
    let knobs = stored_verify_model_knobs(app);
    let gate = knobs
        .get("gateModel")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("not set");
    let panel = knobs
        .get("model")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("workspace model");
    let passes = knobs
        .get("VERIFY_PASSES")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1);
    let escalation = knobs
        .get("escalationModel")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("not set");
    vec![
        format!("gate: {gate} (rejection only)"),
        format!("panel: {panel} x {passes} pass(es)"),
        format!("escalate on tie: {escalation}"),
    ]
}

/// Evidence goals derive from the finding's recorded gaps, so the card only
/// promises work this finding actually needs.
fn investigation_evidence_goals(
    finding: &kuzushi_core::Finding,
    proof: Option<&ProofReplayModel>,
    boundary: crate::app::InvestigationBoundary,
) -> Vec<String> {
    let mut goals = Vec::new();
    if finding.evidence.is_empty() {
        goals.push("Recover structured evidence anchors (source and sink lines)".to_string());
    }
    if finding.corroboration_count <= 1 && finding.sources.len() <= 1 {
        goals.push("Corroborate the signal through an independent source".to_string());
    }
    let has_runtime_attempt = finding
        .verification
        .as_ref()
        .is_some_and(PersistedVerification::has_terminal_runtime_verification);
    if boundary == crate::app::InvestigationBoundary::LocalReproduction {
        append_runtime_investigation_goals(&mut goals, has_runtime_attempt, proof);
    }
    goals.push("Record the verifier verdict and rationale as durable evidence".to_string());
    goals
}

/// Only an explicitly selected local-reproduction run can promise runtime work.
fn append_runtime_investigation_goals(
    goals: &mut Vec<String>,
    has_runtime_attempt: bool,
    proof: Option<&ProofReplayModel>,
) {
    match (has_runtime_attempt, proof) {
        (false, _) => {
            goals.push("Attempt safe reproduction and record a runtime witness".to_string())
        }
        (true, Some(replay)) if replay.requires_revalidation => {
            goals.push("Re-validate the stale proof against the current observation".to_string());
        }
        _ => {}
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
        stages: verification
            .notes
            .iter()
            .find_map(|note| kuzushi_core::parse_stage_note(note)),
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
            .cached_run_artifact_text(target, run_id, "items.jsonl"),
        ViewDataState::Ready(RunArtifactRead::Ready { value, .. }) if !value.is_empty()
    )
}

#[cfg(test)]
mod investigation_goal_tests {
    use super::*;
    use kuzushi_core::{
        Finding, PersistedProofVerdict, PersistedSandboxBackend, PersistedVerification, Severity,
    };

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
            stages: None,
            created_at: "now".to_string(),
            provenance_run_id: None,
            replay_run_id: None,
            requires_revalidation,
        }
    }

    #[test]
    fn static_only_goals_never_promise_a_runtime_witness() {
        let goals = investigation_evidence_goals(
            &bare_finding(),
            None,
            crate::app::InvestigationBoundary::StaticOnly,
        );
        assert!(goals.iter().any(|goal| goal.contains("evidence anchors")));
        assert!(!goals.iter().any(|goal| goal.contains("runtime witness")));
        assert!(!goals.iter().any(|goal| goal.contains("safe reproduction")));
    }

    #[test]
    fn static_only_does_not_promise_to_refresh_stale_runtime_proof() {
        let mut finding = bare_finding();
        finding.verification = Some(crate::test_support::test_empirical_verification(3));
        let goals = investigation_evidence_goals(
            &finding,
            Some(&replay(true)),
            crate::app::InvestigationBoundary::StaticOnly,
        );
        assert!(!goals.iter().any(|goal| goal.contains("stale proof")));
    }

    #[test]
    fn unproven_uncorroborated_finding_derives_every_gap_as_a_goal() {
        let goals = investigation_evidence_goals(
            &bare_finding(),
            None,
            crate::app::InvestigationBoundary::LocalReproduction,
        );
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
        let mut finding = bare_finding();
        let mut verification = crate::test_support::test_empirical_verification(3);
        verification.verified_scan_id = finding.scan_id.clone();
        finding.verification = Some(verification);

        let fresh = investigation_evidence_goals(
            &finding,
            Some(&replay(false)),
            crate::app::InvestigationBoundary::LocalReproduction,
        );
        assert!(!fresh.iter().any(|goal| goal.contains("runtime witness")));
        assert!(!fresh.iter().any(|goal| goal.contains("stale proof")));

        let stale = investigation_evidence_goals(
            &finding,
            Some(&replay(true)),
            crate::app::InvestigationBoundary::LocalReproduction,
        );
        assert!(stale.iter().any(|goal| goal.contains("stale proof")));
    }

    #[test]
    fn model_assessment_keeps_runtime_witness_as_an_open_goal() {
        let mut finding = bare_finding();
        finding.verification = Some(PersistedVerification {
            proof_level: 3,
            proof_verdict: PersistedProofVerdict::NotAttempted,
            backend: PersistedSandboxBackend::Model,
            language: None,
            harness_path: None,
            crash_evidence: None,
            duration_ms: 1,
            cost_usd: 0.0,
            notes: Vec::new(),
            verification_run_id: Some("model-run".to_string()),
            verified_scan_id: Some("scan-1".to_string()),
            provenance: None,
            created_at: "now".to_string(),
        });

        let goals = investigation_evidence_goals(
            &finding,
            Some(&replay(false)),
            crate::app::InvestigationBoundary::LocalReproduction,
        );
        assert!(goals.iter().any(|goal| goal.contains("runtime witness")));
    }
}
