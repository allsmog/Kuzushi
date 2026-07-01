use super::*;

#[test]
fn strategy_queue_path_lives_under_workspace_v2_state() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();

    assert_eq!(
        strategy_queue_path(&workspace),
        workspace.root().join(".kuzushi/v2/strategy-queue.jsonl")
    );
}

#[test]
fn strategy_queue_round_trips_and_updates_status() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let proposal = StrategyProposal::new(
        StrategyPhase::Review,
        "semgrep:scan plus codeql:scan",
        "small repository with indexed languages",
    )
    .with_tool("codeql:scan", Some(serde_json::json!({"target":"."})))
    .with_preflight(StrategyPreflight::ready());

    append_strategy_proposal(&workspace, &proposal).unwrap();
    let loaded = load_strategy_queue(&workspace).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].status, StrategyProposalStatus::Proposed);
    assert_eq!(loaded[0].preflight.status, StrategyPreflightStatus::Ready);

    assert!(set_strategy_proposal_status(
        &workspace,
        &proposal.id,
        StrategyProposalStatus::Approved,
    )
    .unwrap());
    let updated = load_strategy_queue(&workspace).unwrap();
    assert_eq!(updated[0].status, StrategyProposalStatus::Approved);
}

#[test]
fn strategy_corrections_round_trip_and_apply_workspace_scope() {
    let (_temp, workspace, correction) = workspace_with_recorded_strategy_correction();

    assert_recorded_workspace_correction(&workspace, &correction);
    assert_workspace_correction_applies_to_rerun(&workspace);
}

#[test]
fn run_scoped_strategy_correction_applies_only_to_matching_run() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    append_strategy_correction(&workspace, &run_scoped_correction()).unwrap();
    let mut proposals = vec![semgrep_strategy_proposal()];

    apply_strategy_corrections(&workspace, Some("run-2"), &mut proposals).unwrap();
    assert_eq!(proposals[0].corrected_strategy, None);

    apply_strategy_corrections(&workspace, Some("run-1"), &mut proposals).unwrap();
    assert_eq!(
        proposals[0].corrected_strategy.as_deref(),
        Some("run semgrep:scan with routes only")
    );
}

#[test]
fn strategy_queue_missing_file_is_empty() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();

    assert!(load_strategy_queue(&workspace).unwrap().is_empty());
}

fn workspace_with_recorded_strategy_correction() -> (
    tempfile::TempDir,
    WorkspaceTarget,
    StrategyCorrection,
) {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut proposal = StrategyProposal::new(
        StrategyPhase::Review,
        "run codeql:scan",
        "language coverage exists",
    );
    proposal.id = "review-codeql-scan".to_string();
    append_strategy_proposal(&workspace, &proposal).unwrap();
    let correction = workspace_strategy_correction();
    record_strategy_correction(&workspace, &correction).unwrap();
    (temp, workspace, correction)
}

fn workspace_strategy_correction() -> StrategyCorrection {
    StrategyCorrection::new(
        StrategyPhase::Review,
        Some("review-codeql-scan".to_string()),
        "run codeql:scan",
        "run codeql:scan with authz focus",
        StrategyCorrectionScope::Workspace,
        None,
        "tighten this phase to authz paths",
        "operator",
    )
}

fn assert_recorded_workspace_correction(
    workspace: &WorkspaceTarget,
    correction: &StrategyCorrection,
) {
    let corrections = load_strategy_corrections(workspace).unwrap();
    assert_eq!(corrections.len(), 1);
    assert_eq!(corrections[0].scope, StrategyCorrectionScope::Workspace);
    let queue = load_strategy_queue(workspace).unwrap();
    assert_eq!(
        queue[0].corrected_strategy.as_deref(),
        Some("run codeql:scan with authz focus")
    );
    assert_eq!(queue[0].applied_corrections[0].reason, correction.reason);
}

fn assert_workspace_correction_applies_to_rerun(workspace: &WorkspaceTarget) {
    let mut rerun = vec![codeql_strategy_proposal_for_rerun()];

    apply_strategy_corrections(workspace, Some("run-2"), &mut rerun).unwrap();

    assert_eq!(
        rerun[0].corrected_strategy.as_deref(),
        Some("run codeql:scan with authz focus")
    );
}

fn codeql_strategy_proposal_for_rerun() -> StrategyProposal {
    StrategyProposal {
        id: "review-codeql-scan".to_string(),
        phase: StrategyPhase::Review,
        base_strategy: "module recommender defaults".to_string(),
        recommended_strategy: "run codeql:scan".to_string(),
        corrected_strategy: None,
        applied_corrections: Vec::new(),
        rationale: "language coverage exists".to_string(),
        expected_cost_usd: None,
        expected_runtime: None,
        preflight: StrategyPreflight::ready(),
        resource_risk: StrategyResourceRisk::Low,
        status: StrategyProposalStatus::Proposed,
        source_run_id: Some("run-2".to_string()),
        tool: Some("codeql:scan".to_string()),
        next_input: None,
        created_at_ms: 1,
        updated_at_ms: 1,
    }
}

fn run_scoped_correction() -> StrategyCorrection {
    StrategyCorrection::new(
        StrategyPhase::Review,
        Some("review-semgrep-scan".to_string()),
        "run semgrep:scan",
        "run semgrep:scan with routes only",
        StrategyCorrectionScope::Run,
        Some("run-1".to_string()),
        "single run correction",
        "operator",
    )
}

fn semgrep_strategy_proposal() -> StrategyProposal {
    let mut proposal = StrategyProposal::new(StrategyPhase::Review, "run semgrep:scan", "fast pass");
    proposal.id = "review-semgrep-scan".to_string();
    proposal
}
