use super::*;
use kuzushi_core::{
    append_strategy_proposal, StrategyPhase, StrategyPreflight, StrategyProposal,
    StrategyProposalStatus, StrategyResourceRisk, V2Config,
};

#[test]
fn strategy_queue_model_requires_target() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = strategy_queue_model(&app);

    assert_eq!(
        model.summary,
        "no target selected; strategy queue is target-scoped"
    );
    assert_eq!(model.empty_state.title, "no target selected");
    assert!(model.rows.is_empty());
}

#[test]
fn strategy_queue_not_requested_does_not_claim_to_be_loading() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));

    let model = strategy_queue_model(&app);

    assert_eq!(
        model.summary,
        "strategy queue has not been loaded; open `recommendations` to inspect suggestions"
    );
}

#[test]
fn strategy_queue_model_reads_persisted_proposals() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut proposal = StrategyProposal::new(
        StrategyPhase::Review,
        "run codeql:scan",
        "small enough repository with CodeQL language coverage",
    )
    .with_estimates(
        None,
        Some("local pass".to_string()),
        StrategyResourceRisk::Low,
    )
    .with_preflight(StrategyPreflight::ready())
    .with_source_run(Some("rec-123".to_string()));
    proposal.id = "review-codeql-scan".to_string();
    append_strategy_proposal(&workspace, &proposal).unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();
    let model = strategy_queue_model(&app);

    assert_eq!(
        model.summary,
        "1 proposals: 1 proposed, 0 approved, 0 running, 0 done, 0 failed, 0 rejected, 0 corrected"
    );
    assert_eq!(model.rows[0].id, "review-codeql-scan");
    assert_eq!(model.rows[0].cells[0], "proposed");
    assert_eq!(model.rows[0].cells[1], "review");
    assert_eq!(model.rows[0].cells[3], "run codeql:scan");
    assert_eq!(model.rows[0].cells[4], "-");
    assert_eq!(model.rows[0].cells[5], "-");
    assert_eq!(model.rows[0].cells[8], "-");
    assert_eq!(model.rows[0].cells[9], "ready");
    assert_eq!(model.rows[0].cells[10], "local pass");
    assert_eq!(model.rows[0].cells[11], "low");
    assert_eq!(model.rows[0].source_run, "rec-123");
}

#[test]
fn retained_approval_result_and_unknown_cost_are_explicit_in_the_queue() {
    let mut proposal = StrategyProposal::new(
        StrategyPhase::Review,
        "run context:build",
        "retained metadata",
    );
    proposal.status = StrategyProposalStatus::Done;
    proposal.approved_cost_usd = Some(0.5);
    proposal.actual_cost_usd = Some(0.2);
    proposal.result_run_id = Some("owned-result".into());
    proposal.tool = Some("context:build".into());
    let row = strategy_row_from_proposal(proposal);
    assert_eq!(row.approved_cost, "$0.5000");
    assert_eq!(row.cells[7], "$0.2000");
    assert_eq!(row.result_run, "owned-result");
    assert_eq!(row.tool, "context:build");
    assert_eq!(cost_label(None), "unknown");
    for cost in [-1.0, f64::NAN, f64::INFINITY] {
        assert_eq!(cost_label(Some(cost)), "unknown");
    }
}

#[test]
fn proposal_inspection_is_read_only_target_bound_and_discloses_unknown_ids() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut proposal =
        StrategyProposal::new(StrategyPhase::Review, "run context:build", "owned metadata");
    proposal.id = "owned-inspect".into();
    proposal.status = StrategyProposalStatus::Done;
    proposal.result_run_id = Some("owned-result".into());
    append_strategy_proposal(&workspace, &proposal).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_input("held inspection draft");
    let effects = app
        .reduce_command_effects(&crate::commands::parse_command(
            "strategy inspect owned-inspect",
        ))
        .unwrap();
    assert!(effects.is_empty());
    app.hydrate_all_view_data_for_test();
    let model = strategy_queue_model(&app);
    assert_eq!(model.title, "STRATEGY PROPOSAL");
    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].result_run, "owned-result");
    assert_eq!(app.input(), "held inspection draft");
    assert!(!app.tool_is_running());
    app.reduce_command_effects(&crate::commands::parse_command("strategy inspect unknown"))
        .unwrap();
    app.hydrate_all_view_data_for_test();
    assert!(strategy_queue_model(&app).rows[0]
        .rationale
        .contains("No proposal named unknown"));
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().to_path_buf()));
    assert_eq!(app.inspected_strategy_id(), None);
}

#[test]
fn new_drafts_sort_before_older_unreviewed_suggestions() {
    let mut old = StrategyProposal::new_at(1, StrategyPhase::Review, "run context:build", "old");
    old.id = "old".into();
    let mut new = StrategyProposal::new_at(2, StrategyPhase::Review, "run context:build", "new");
    new.id = "new".into();
    let rows = strategy_rows_from_proposals(vec![old, new]);
    assert_eq!(rows[0].id, "new");
    assert_eq!(rows[1].id, "old");
}

#[test]
fn loaded_empty_queue_discloses_a_requested_missing_identity() {
    let rows = inspected_rows(Vec::new(), Some("missing"), true);
    assert!(rows[0].rationale.contains("No proposal named missing"));
    assert!(inspected_rows(Vec::new(), Some("missing"), false).is_empty());
}

#[test]
fn reopening_strategy_reads_external_decisions_and_preserves_composer_draft() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();
    assert!(strategy_queue_model(&app).rows.is_empty());
    let mut proposal =
        StrategyProposal::new(StrategyPhase::Review, "run context:build", "owned metadata");
    proposal.status = StrategyProposalStatus::Approved;
    append_strategy_proposal(&workspace, &proposal).unwrap();
    app.set_input("held queue draft");
    let effects = app
        .reduce_command_effects(&crate::commands::parse_command("strategy"))
        .unwrap();
    assert!(effects.is_empty());
    app.hydrate_all_view_data_for_test();
    assert_eq!(strategy_queue_model(&app).rows[0].cells[0], "approved");
    assert_eq!(app.input(), "held queue draft");
    assert!(!app.tool_is_running());
}

#[test]
fn strategy_queue_model_sorts_proposed_before_approved_and_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut approved = StrategyProposal::new(StrategyPhase::Review, "run semgrep:scan", "fast");
    approved.id = "review-semgrep-scan".to_string();
    approved.status = StrategyProposalStatus::Approved;
    let mut proposed = StrategyProposal::new(StrategyPhase::Review, "run codeql:scan", "deep");
    proposed.id = "review-codeql-scan".to_string();
    let mut rejected = StrategyProposal::new(StrategyPhase::Review, "run slow:scan", "too big");
    rejected.id = "review-slow-scan".to_string();
    rejected.status = StrategyProposalStatus::Rejected;
    append_strategy_proposal(&workspace, &approved).unwrap();
    append_strategy_proposal(&workspace, &rejected).unwrap();
    append_strategy_proposal(&workspace, &proposed).unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();
    let model = strategy_queue_model(&app);

    assert_eq!(model.rows[0].id, "review-codeql-scan");
    assert_eq!(model.rows[1].id, "review-semgrep-scan");
    assert_eq!(model.rows[2].id, "review-slow-scan");
}
