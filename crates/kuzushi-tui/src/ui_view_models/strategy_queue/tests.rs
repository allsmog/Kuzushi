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
