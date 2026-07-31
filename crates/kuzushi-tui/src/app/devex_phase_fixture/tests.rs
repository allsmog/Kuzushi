use super::*;

fn fixture_app(target: &Path) -> ShellApp {
    let workspace = WorkspaceTarget::new(target).expect("fixture workspace");
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-5.4".to_string());
    ShellApp::new(config, Some(&workspace))
}

#[test]
fn devex_phase_fixture_requires_an_explicit_truthy_hook() {
    for value in [
        Some("1"),
        Some("true"),
        Some("YES"),
        Some(" on "),
        Some("live"),
        Some("settled"),
    ] {
        assert!(devex_phase_fixture_requested(value));
    }
    for value in [None, Some(""), Some("0"), Some("false"), Some("phase")] {
        assert!(!devex_phase_fixture_requested(value));
    }
}

#[test]
fn devex_phase_fixture_lifecycle_is_explicit() {
    assert_eq!(
        devex_phase_fixture_lifecycle(Some("live")),
        Some(PhaseFixtureLifecycle::Live)
    );
    assert_eq!(
        devex_phase_fixture_lifecycle(Some("true")),
        Some(PhaseFixtureLifecycle::Settled)
    );
}

#[test]
fn devex_hook_refuses_non_demo_targets_without_writing_fixture_data() {
    let target = tempfile::tempdir().expect("non-demo target");
    let mut app = fixture_app(target.path());

    app.seed_devex_phase_fixture_for_value(Some("1"));

    assert!(app.findings().is_empty());
    assert!(!target.path().join("src/auth/login.rs").exists());
    assert!(app
        .log_lines()
        .iter()
        .any(|line| { line.body.contains("active target is not the offline demo") }));
}

#[test]
fn live_and_settled_reference_lifecycles_are_truthful() {
    let live_target = tempfile::tempdir().expect("live target");
    let mut live = fixture_app(live_target.path());
    seed_pdf_phase_reference_fixture(&mut live, live_target.path(), PhaseFixtureLifecycle::Live)
        .expect("live fixture");
    let live_activity = live.activity().expect("live activity");
    assert!(live_activity.completed_at.is_none());
    assert!(live_activity
        .tasks
        .values()
        .any(|row| row.state == DagTaskState::Active));

    let settled_target = tempfile::tempdir().expect("settled target");
    let mut settled = fixture_app(settled_target.path());
    seed_pdf_phase_reference_fixture(
        &mut settled,
        settled_target.path(),
        PhaseFixtureLifecycle::Settled,
    )
    .expect("settled fixture");
    let settled_activity = settled.activity().expect("settled activity");
    assert_eq!(settled_activity.elapsed_secs(), 42);
    assert!(settled_activity.completed_at.is_some());
    assert!(settled_activity
        .tasks
        .values()
        .all(|row| row.state == DagTaskState::Done));
}

#[test]
fn shared_reference_seed_populates_every_phase_projection() {
    let target = tempfile::tempdir().expect("reference target");
    let mut app = fixture_app(target.path());
    seed_pdf_phase_reference_fixture(&mut app, target.path(), PhaseFixtureLifecycle::Settled)
        .expect("reference fixture");

    assert_eq!(app.findings().len(), 6);
    assert!(app
        .selected_finding()
        .as_ref()
        .and_then(|finding| finding.verification.as_ref())
        .is_some_and(|proof| proof.verification_run_id.as_deref() == Some("verify-phase-run")));
    assert!(app
        .domain()
        .taint_flow_for_finding(app.selected_finding().as_ref().expect("selected finding"))
        .is_some());
    assert_eq!(app.domain().exploit_chains().len(), 1);
    assert!(app.engagement.pending_patch().is_some());
    assert_eq!(app.activity().expect("activity").event_count(), 10);
    assert_eq!(app.session().session_budget_usd(), Some(2.0));
    let journey = crate::ui_view_models::journey_model(&app).expect("fixture journey");
    assert!(journey.progress.map_artifacts_built);
    assert_eq!(journey.progress.finding_total, 6);
    assert_eq!(journey.progress.reviewed_findings, 0);
    assert_eq!(journey.progress.confirmed_findings, 0);
    assert_eq!(journey.current, WorkflowPhase::Review);
    assert!(journey
        .next_action
        .contains("record terminal dispositions for 6 of 6 ledger candidates"));
}

#[test]
fn f4_seeds_escalated_and_refused_split_verdicts_and_stage_runs() {
    let target = tempfile::tempdir().expect("f4 target");
    let mut app = fixture_app(target.path());
    seed_pdf_phase_reference_fixture(&mut app, target.path(), PhaseFixtureLifecycle::Settled)
        .expect("reference fixture");

    // (a) an ESCALATED split disclosure on a seeded finding, still model-assessed.
    let escalated = app
        .findings()
        .iter()
        .find(|finding| finding.fingerprint == findings::ESCALATED_FINGERPRINT)
        .and_then(|finding| finding.verification.clone())
        .expect("escalated finding present");
    assert!(escalated.is_model_assessment(), "escalation never promotes");
    let escalated_stages = escalated
        .notes
        .iter()
        .find_map(|note| kuzushi_core::parse_stage_note(note))
        .expect("escalated stage note");
    assert!(escalated_stages.split);
    assert_eq!(
        escalated_stages.escalation.as_deref(),
        Some(findings::ESCALATION_MODEL)
    );
    assert_eq!(escalated_stages.refused, None);

    // (b) a REFUSED (SameModelAsPrimary) split disclosure, verdict unchanged.
    let refused = app
        .findings()
        .iter()
        .find(|finding| finding.fingerprint == findings::REFUSED_FINGERPRINT)
        .and_then(|finding| finding.verification.clone())
        .expect("refused finding present");
    assert!(refused.is_model_assessment());
    let refused_stages = refused
        .notes
        .iter()
        .find_map(|note| kuzushi_core::parse_stage_note(note))
        .expect("refused stage note");
    assert!(refused_stages.refused.is_some());
    assert_eq!(refused_stages.escalation, None);

    // (c) two seeded run dirs whose items.jsonl carry the ordered stage labels.
    let escalated_run = std::fs::read_to_string(
        kuzushi_core::run_dir(target.path(), findings::ESCALATED_RUN_ID).join("items.jsonl"),
    )
    .expect("escalated run items");
    assert!(escalated_run.contains("gate · plausibility (openai:gpt-cheap) · rejection only"));
    assert!(escalated_run.contains("panel · 2 pass(es) (openai:gpt-verify)"));
    assert!(escalated_run.contains("escalation · tie-break (openai:gpt-strong)"));

    let refused_run = std::fs::read_to_string(
        kuzushi_core::run_dir(target.path(), findings::REFUSED_RUN_ID).join("items.jsonl"),
    )
    .expect("refused run items");
    assert!(refused_run.contains("gate · plausibility (openai:gpt-cheap) · rejection only"));
    assert!(refused_run.contains("panel · 2 pass(es) (openai:gpt-verify)"));
    // A refused escalation must never appear as a completed escalation stage.
    assert!(!refused_run.contains("escalation · tie-break ("));
    assert!(refused_run.contains("refused"));
}

#[test]
fn f4_seeds_audited_dataflow_evidence_with_a_falsifying_guard_off_a_cpg_path() {
    let target = tempfile::tempdir().expect("f4 dataflow target");
    let mut app = fixture_app(target.path());
    seed_pdf_phase_reference_fixture(&mut app, target.path(), PhaseFixtureLifecycle::Settled)
        .expect("reference fixture");

    // The seeded finding is present under its stable fingerprint.
    assert!(app
        .findings()
        .iter()
        .any(|finding| finding.fingerprint == findings::AUDITED_FINGERPRINT));

    // The deep-audit:evidence audit events project into source/sink/guard rows,
    // and the guard is a falsifying witness mined off a cpg-rs path — the shape
    // the AUDITED DATAFLOW section renders. Read through the same service the
    // detail-pane hydration uses.
    let rows =
        crate::app::finding_audit_dataflow_for_target(target.path(), findings::AUDITED_FINGERPRINT)
            .expect("audit dataflow read")
            .expect("finding present");
    assert_eq!(rows.len(), 3, "source + sink + guard");
    let guard = rows
        .iter()
        .find(|row| row.kind == "guard")
        .expect("guard row");
    assert_eq!(guard.origin, "deep auditor (cpg-rs path)");
    assert!(guard.note.starts_with("falsifying evidence · "));
}

#[test]
fn reference_seed_invalidates_missing_dfd_and_replay_cache_entries() {
    let target = tempfile::tempdir().expect("cache target");
    let mut app = fixture_app(target.path());
    assert!(crate::ui_view_models::dfd_model(&app).empty_hint.is_some());
    assert!(matches!(
        app.workbench_cache().borrow_mut().run_artifact_text(
            target.path(),
            "verify-phase-run",
            "items.jsonl"
        ),
        kuzushi_core::RunArtifactRead::Missing { .. }
    ));

    seed_pdf_phase_reference_fixture(&mut app, target.path(), PhaseFixtureLifecycle::Settled)
        .expect("reference fixture");

    assert!(crate::ui_view_models::dfd_model(&app).empty_hint.is_none());
    assert!(matches!(
        app.workbench_cache().borrow_mut().run_artifact_text(
            target.path(),
            "verify-phase-run",
            "items.jsonl"
        ),
        kuzushi_core::RunArtifactRead::Ready { .. }
    ));
}

#[test]
fn persisted_reference_projection_survives_workspace_refresh() {
    let target = tempfile::tempdir().expect("refresh target");
    let mut app = fixture_app(target.path());
    let workspace = WorkspaceTarget::new(target.path()).expect("prior workspace");
    let store =
        kuzushi_core::FindingStore::open(workspace.findings_db_path()).expect("prior store");
    let prior = Finding::new_tool(
        "demo",
        "prior.rule",
        "prior.rs",
        1,
        None,
        kuzushi_core::Severity::High,
        "prior finding",
    );
    store
        .record_run_started("prior-run", target.path(), "running")
        .expect("prior run");
    store
        .insert_finding("prior-run", &prior)
        .expect("prior finding");
    store
        .record_run_finished("prior-run", "completed", 1)
        .expect("prior completion");
    drop(store);
    seed_pdf_phase_reference_fixture(&mut app, target.path(), PhaseFixtureLifecycle::Settled)
        .expect("reference fixture");

    app.refresh_findings(false);

    assert_eq!(app.findings().len(), 6);
    let selected = app.selected_finding().as_ref().expect("selected finding");
    assert!(selected.verification.is_some());
    assert!(app.domain().taint_flow_for_finding(selected).is_some());
    let model = crate::ui_view_models::phase_cockpit_model_for_phase(&app, WorkflowPhase::Prove);
    let crate::ui_view_models::PhaseCockpitBody::Prove(prove) = model.body else {
        panic!("Prove body")
    };
    assert!(prove.proof.is_some_and(|proof| proof.has_replay()));
}
