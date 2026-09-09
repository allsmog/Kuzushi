use super::*;

#[test]
fn completed_setup_map_accepts_the_displayed_attempt_after_refresh() {
    let (target, mut app) = completed_map();
    assert!(app.finalize_run_focus_if_idle());
    let displayed = app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Map)
        .unwrap()
        .completed
        .attempt_id
        .clone();
    crate::test_support::record_indexed_run(
        target.path(),
        "newer-map",
        "context:build",
        serde_json::json!({"ok": true, "data": {"snapshot": {"filesIndexed": 1}}}),
    );
    let newer = crate::test_support::append_typed_attempt(
        target.path(),
        WorkflowPhase::Map,
        "newer-map",
        PhaseAttemptOutcome::Completed,
    );
    app.apply_phase_result_command(crate::app::PhaseResultCommand::Select);
    assert_eq!(
        app.engagement
            .selected_phase_attempt(WorkflowPhase::Map)
            .unwrap()
            .completed
            .attempt_id,
        displayed
    );
    assert!(app
        .engagement
        .unresolved_phase_attempt_by_id(WorkflowPhase::Map, &newer.attempt_id,)
        .is_some());
}

#[test]
fn completed_setup_map_keeps_unverifiable_result_open_instead_of_accepting_it() {
    let (_target, mut app) = map_fixture(false);
    assert!(app.finalize_run_focus_if_idle());
    assert_selection_blocked(&mut app);
}

fn assert_selection_blocked(app: &mut ShellApp) {
    let policy = app
        .projected_phase_result_policy(WorkflowPhase::Map)
        .unwrap();
    assert!(!policy.actions.contains(&PhaseResultAction::Select));
    assert!(policy.recommended_next.unwrap().contains("source"));
    app.apply_phase_result_command(crate::app::PhaseResultCommand::Select);
    assert!(app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Map)
        .is_some());
    assert!(app
        .engagement
        .selected_phase_attempt(WorkflowPhase::Map)
        .is_none());
}

#[test]
fn completed_setup_map_rechecks_source_changes_before_acceptance() {
    let (target, mut app) = completed_map();
    assert!(app.finalize_run_focus_if_idle());
    let before = attempt_ledger_bytes(target.path());
    std::fs::write(target.path().join("lib.rs"), "pub fn changed() {}\n").unwrap();
    app.apply_phase_result_command(crate::app::PhaseResultCommand::Select);
    assert_selection_blocked(&mut app);
    assert_eq!(attempt_ledger_bytes(target.path()), before);
}

fn attempt_ledger_bytes(target: &std::path::Path) -> Vec<Vec<u8>> {
    ["phase-attempts.jsonl", "phase-attempts.v2.jsonl"]
        .iter()
        .map(|name| std::fs::read(target.join(".kuzushi/v3/workflow").join(name)).unwrap())
        .collect()
}

#[test]
fn completed_setup_map_acceptance_advances_and_survives_restart() {
    let (target, mut app) = completed_map();
    assert!(app.finalize_run_focus_if_idle());
    app.apply_phase_result_command(crate::app::PhaseResultCommand::Select);
    assert!(app
        .engagement
        .selected_phase_attempt(WorkflowPhase::Map)
        .is_some());
    assert_eq!(
        crate::ui_view_models::journey_model(&app).unwrap().current,
        WorkflowPhase::Scan
    );
    let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
    let mut restarted = ShellApp::new(V2Config::default(), Some(&workspace));
    restarted.hydrate_all_view_data_for_test();
    assert!(restarted
        .engagement
        .selected_phase_attempt(WorkflowPhase::Map)
        .is_some());
    assert_eq!(
        crate::ui_view_models::journey_model(&restarted)
            .unwrap()
            .current,
        WorkflowPhase::Scan
    );
}
