use super::*;
use crate::{ActivitySession, DagTaskRow, DagTaskState, PendingPatch};
use kuzushi_core::{
    Finding, PersistedProofVerdict, PersistedSandboxBackend, PersistedVerification, RunTraceStep,
    Severity, V2Config, WorkspaceTarget,
};

fn finding() -> Finding {
    Finding::new_tool(
        "semgrep",
        "rust/sql-injection",
        "src/auth/login.rs",
        17,
        None,
        Severity::High,
        "query reaches the database",
    )
}

fn verification() -> PersistedVerification {
    PersistedVerification {
        proof_level: 3,
        proof_verdict: PersistedProofVerdict::Exploited,
        backend: PersistedSandboxBackend::Plain,
        language: Some("rust".to_string()),
        harness_path: Some(".kuzushi/harness.rs".to_string()),
        crash_evidence: Some("reproduced SQL execution".to_string()),
        duration_ms: 420,
        cost_usd: 0.07,
        notes: vec!["isolated harness".to_string()],
        verification_run_id: Some("verify-run".to_string()),
        verified_scan_id: Some("run-proof".to_string()),
        created_at: "2026-07-09T10:00:00Z".to_string(),
    }
}

#[test]
fn activity_session_phase_origin_is_explicit_and_transient() {
    assert_eq!(ActivitySession::new("run-1").origin_phase, None);
    assert_eq!(
        ActivitySession::for_phase("run-2", WorkflowPhase::Hunt).origin_phase,
        Some(WorkflowPhase::Hunt)
    );
    assert_eq!(
        ActivitySession::new("run-3")
            .with_origin_phase(WorkflowPhase::Confirm)
            .origin_phase,
        Some(WorkflowPhase::Confirm)
    );
    assert_eq!(
        ActivitySession::for_optional_phase("run-4", Some(WorkflowPhase::Fix)).origin_phase,
        Some(WorkflowPhase::Fix)
    );
    assert_eq!(
        ActivitySession::for_optional_phase("run-5", None).origin_phase,
        None
    );
}

#[test]
fn captured_activity_phase_wins_over_missing_or_advanced_journey_state() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_activity(Some(ActivitySession::for_phase(
        "run-fix",
        WorkflowPhase::Fix,
    )));
    assert!(
        phase_cockpit_model(&app).is_none(),
        "an old Activity origin must not freeze another view without a target"
    );
    app.set_shell_view(crate::ShellView::Activity);

    let model = phase_cockpit_model(&app).expect("captured phase");

    assert_eq!(model.phase, WorkflowPhase::Fix);
    assert!(matches!(model.body, PhaseCockpitBody::Fix(_)));
    assert_eq!(
        model.header.next_action,
        "select a target to begin the engagement"
    );
}

#[test]
fn generic_activity_does_not_borrow_the_workspace_journey_phase() {
    let target = tempfile::tempdir().expect("target");
    let workspace = WorkspaceTarget::new(target.path()).expect("workspace");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_activity(Some(ActivitySession::new("generic-run")));
    app.set_shell_view(crate::ShellView::Activity);

    assert_eq!(
        journey_model(&app).expect("target journey").current,
        WorkflowPhase::Map
    );
    assert!(
        phase_cockpit_model(&app).is_none(),
        "generic Activity must retain the legacy TASKS/OUTPUT composition"
    );
}

#[test]
fn map_model_projects_only_observed_trace_tasks_cost_and_budget() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_mut().set_session_cost_usd_for_test(0.5);
    app.session_mut().set_session_budget_usd(Some(1.0));
    let mut session = ActivitySession::for_phase("run-map", WorkflowPhase::Map);
    let mut context = DagTaskRow::queued(
        "context:build".to_string(),
        "context".to_string(),
        Vec::new(),
    );
    context.state = DagTaskState::Done;
    context.cost_usd = 0.25;
    session.tasks.insert(context.task_id.clone(), context);
    session.tasks.insert(
        "threat-model:build".to_string(),
        DagTaskRow::queued(
            "threat-model:build".to_string(),
            "threat-model".to_string(),
            Vec::new(),
        ),
    );
    session.apply_step(RunTraceStep {
        n: 7,
        kind: "reasoning".to_string(),
        label: "indexing routes".to_string(),
        latency_ms: Some(12),
        cost_usd: Some(0.01),
        module_id: Some("context".to_string()),
        verb: Some("build".to_string()),
        parent_step: None,
        severity: None,
        started_at_ms: None,
        model: Some("openai:gpt-5".to_string()),
        provider: Some("openai".to_string()),
        prompt_hash: None,
    });
    app.set_activity(Some(session));

    let model = phase_cockpit_model_for_phase(&app, WorkflowPhase::Map);
    let PhaseCockpitBody::Map(map) = model.body else {
        panic!("expected map body");
    };

    assert_eq!(model.header.cost_usd, 0.5);
    assert_eq!(model.header.budget_usd, Some(1.0));
    assert_eq!(map.run_id.as_deref(), Some("run-map"));
    assert_eq!(map.run_cost_usd, 0.26);
    assert_eq!(map.task_counts.total, 2);
    assert_eq!(map.task_counts.completed, 1);
    assert_eq!(map.task_counts.queued, 1);
    assert_eq!(map.console.len(), 1);
    assert_eq!(map.console[0].sequence, 7);
    assert_eq!(map.console[0].label, "indexing routes");
    assert_eq!(map.console[0].latency_ms, Some(12));
    assert_eq!(map.console[0].cost_usd, Some(0.01));
}

#[test]
fn hunt_models_share_the_projected_selected_finding_identity() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let finding = finding();
    *app.findings_mut() = vec![finding.clone()];
    *app.selected_finding_mut() = Some(finding);

    let model = phase_cockpit_model_for_phase(&app, WorkflowPhase::Hunt);
    let PhaseCockpitBody::Hunt(hunt) = model.body else {
        panic!("expected hunt body");
    };

    assert_eq!(hunt.source.finding_count, 1);
    assert_eq!(hunt.review.rows.len(), 1);
    assert!(hunt.review.rows[0].selected);
    assert_eq!(hunt.heatmap.selected_module.as_deref(), Some("auth"));
}

#[test]
fn confirm_proof_requires_persisted_verification_and_trace_for_replay() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let workspace = WorkspaceTarget::new(tmp.path()).expect("workspace");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let mut selected = finding();
    selected.scan_id = Some("run-proof".to_string());
    *app.findings_mut() = vec![selected.clone()];
    *app.selected_finding_mut() = Some(selected.clone());

    let no_proof = phase_cockpit_model_for_phase(&app, WorkflowPhase::Confirm);
    let PhaseCockpitBody::Confirm(no_proof) = no_proof.body else {
        panic!("expected confirm body");
    };
    assert!(no_proof.proof.is_none());

    selected.verification = Some(verification());
    *app.findings_mut() = vec![selected.clone()];
    *app.selected_finding_mut() = Some(selected.clone());
    let persisted = phase_cockpit_model_for_phase(&app, WorkflowPhase::Confirm);
    let PhaseCockpitBody::Confirm(persisted) = persisted.body else {
        panic!("expected confirm body");
    };
    let proof = persisted.proof.expect("persisted verification");
    assert_eq!(proof.verdict, "exploited");
    assert_eq!(proof.provenance_run_id.as_deref(), Some("verify-run"));
    assert!(!proof.has_replay());
    assert!(!proof.requires_revalidation);

    let run_dir = kuzushi_core::run_dir(tmp.path(), "verify-run");
    std::fs::create_dir_all(&run_dir).expect("run dir");
    std::fs::write(run_dir.join("trace.jsonl"), "{}\n").expect("trace");
    app.hydrate_all_view_data_for_test();
    let replay = phase_cockpit_model_for_phase(&app, WorkflowPhase::Confirm);
    let PhaseCockpitBody::Confirm(replay) = replay.body else {
        panic!("expected confirm body");
    };
    assert!(replay.proof.expect("proof replay").has_replay());

    selected.scan_id = Some("run-after-proof".to_string());
    *app.findings_mut() = vec![selected.clone()];
    *app.selected_finding_mut() = Some(selected);
    let rescanned = phase_cockpit_model_for_phase(&app, WorkflowPhase::Confirm);
    let PhaseCockpitBody::Confirm(rescanned) = rescanned.body else {
        panic!("expected confirm body");
    };
    assert!(
        rescanned
            .proof
            .expect("prior verification")
            .requires_revalidation
    );
}

#[test]
fn fix_model_reuses_review_patch_graph_and_report_projections() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let finding = finding();
    *app.findings_mut() = vec![finding.clone()];
    *app.selected_finding_mut() = Some(finding);
    app.engagement.set_pending_patch(PendingPatch {
        alias: "F-0001".to_string(),
        rationale: "parameterize the query".to_string(),
        side_effect: None,
        diff: "- raw(query)\n+ bind(query)".to_string(),
        tests: vec![("unit".to_string(), "covers injection".to_string())],
        guardrail: None,
        staged_at: None,
    });

    let model = phase_cockpit_model_for_phase(&app, WorkflowPhase::Fix);
    let PhaseCockpitBody::Fix(fix) = model.body else {
        panic!("expected fix body");
    };

    assert_eq!(fix.findings.total, 1);
    assert_eq!(fix.review.total_count, 1);
    assert_eq!(fix.report.counts.total_findings, 1);
    assert_eq!(
        fix.patch.as_ref().map(|patch| patch.alias.as_str()),
        Some("F-0001")
    );
    assert!(fix.attack_tree.empty_hint.is_some());
    assert!(fix.dfd.empty_hint.is_some());
    assert_eq!(fix.export_command, "findings export report.sarif sarif");
}

#[test]
fn inspecting_another_page_does_not_forge_the_next_action() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    app.engagement.clear_phase();
    *app.findings_mut() = vec![finding()];
    assert_eq!(app.findings().len(), 1);
    assert_eq!(
        journey_model(&app).expect("journey").current,
        WorkflowPhase::Confirm
    );

    let model = phase_cockpit_model_for_phase(&app, WorkflowPhase::Map);

    assert_eq!(model.phase, WorkflowPhase::Map);
    assert!(
        model.header.next_action.contains("triage & verify"),
        "{}",
        model.header.next_action
    );
    assert!(!model.header.next_action.contains("establish the grip"));
}
