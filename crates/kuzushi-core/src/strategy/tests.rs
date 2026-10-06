use super::*;

#[test]
fn strategy_queue_path_lives_under_workspace_v2_state() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();

    assert_eq!(
        strategy_queue_path(&workspace),
        workspace.root().join(".kuzushi/v3/strategy-queue.jsonl")
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

#[test]
fn direct_strategy_load_initializes_ignored_state() {
    let temp = tempfile::tempdir().unwrap();
    if !initialize_git_fixture(temp.path()) {
        return;
    }
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();

    assert!(load_strategy_queue(&workspace).unwrap().is_empty());

    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(temp.path())
        .args(["status", "--porcelain", "--untracked-files=all"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "strategy load dirtied fresh repository: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn initialize_git_fixture(root: &std::path::Path) -> bool {
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .is_ok_and(|output| output.status.success())
    };
    git(&["init", "-q"])
        && git(&["config", "user.email", "test@example.com"])
        && git(&["config", "user.name", "Kuzushi Test"])
        && std::fs::write(root.join("README.md"), "fixture\n").is_ok()
        && git(&["add", "README.md"])
        && git(&["commit", "-q", "-m", "initial"])
}

#[cfg(unix)]
#[test]
fn strategy_ledgers_reject_symlinks_without_touching_their_targets() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    workspace.ensure_state_dir().unwrap();
    std::fs::write(outside.path(), "OUTSIDE_STRATEGY_TOKEN").unwrap();
    symlink(outside.path(), strategy_queue_path(&workspace)).unwrap();

    let proposal = StrategyProposal::new(
        StrategyPhase::Review,
        "run semgrep:scan",
        "exercise the safe state boundary",
    );
    assert!(load_strategy_queue(&workspace).is_err());
    assert!(save_strategy_queue(&workspace, &[proposal]).is_err());
    assert_eq!(
        std::fs::read_to_string(outside.path()).unwrap(),
        "OUTSIDE_STRATEGY_TOKEN"
    );
}

#[test]
fn concurrent_strategy_appends_do_not_lose_updates() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let handles = (0..8)
        .map(|index| {
            let workspace = workspace.clone();
            std::thread::spawn(move || {
                let mut proposal = StrategyProposal::new(
                    StrategyPhase::Review,
                    format!("strategy-{index}"),
                    "concurrency regression",
                );
                proposal.id = format!("proposal-{index}");
                append_strategy_proposal(&workspace, &proposal).unwrap();
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().unwrap();
    }

    let proposals = load_strategy_queue(&workspace).unwrap();
    assert_eq!(proposals.len(), 8);
}

#[test]
fn oversized_strategy_write_is_rejected_before_installation() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let proposal = StrategyProposal::new(
        StrategyPhase::Review,
        "run semgrep:scan",
        "x".repeat(5 * 1024 * 1024),
    );

    let error = save_strategy_queue(&workspace, &[proposal]).unwrap_err();

    assert!(error.to_string().contains("write limit"));
    assert!(load_strategy_queue(&workspace).unwrap().is_empty());
}

#[test]
fn pending_strategy_transaction_is_completed_before_reads() {
    use super::persistence::{
        begin_strategy_transaction, encode_strategy_jsonl, write_strategy_jsonl_body,
    };

    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let proposal = semgrep_strategy_proposal();
    let correction = workspace_strategy_correction();
    let queue_body = encode_strategy_jsonl(&[proposal], "strategy proposal").unwrap();
    let corrections_body = encode_strategy_jsonl(&[correction], "strategy correction").unwrap();
    begin_strategy_transaction(&workspace, queue_body, corrections_body.clone()).unwrap();
    write_strategy_jsonl_body(
        &workspace,
        STRATEGY_CORRECTIONS_FILE,
        corrections_body.as_bytes(),
    )
    .unwrap();

    assert_eq!(load_strategy_queue(&workspace).unwrap().len(), 1);
    assert_eq!(load_strategy_corrections(&workspace).unwrap().len(), 1);
}

#[test]
fn strategy_proposal_records_execution_outcome() {
    let mut proposal = StrategyProposal::new(
        StrategyPhase::Review,
        "run semgrep:scan",
        "cheap coverage first",
    )
    .with_yield_score(Some(0.75))
    .with_estimated_rounds(Some(3))
    .with_approved_cost(Some(1.50));

    proposal.mark_running();
    assert_eq!(proposal.status, StrategyProposalStatus::Running);

    proposal.mark_done(Some("run-123".to_string()), Some(1.20), Some(8), Some(3));

    assert_eq!(proposal.status, StrategyProposalStatus::Done);
    assert_eq!(proposal.result_run_id.as_deref(), Some("run-123"));
    assert_eq!(proposal.actual_cost_usd, Some(1.20));
    assert_eq!(proposal.findings_count, Some(8));
    assert_eq!(proposal.confirmed_count, Some(3));
    assert_eq!(proposal.failure, None);
}

#[test]
fn strategy_cost_helpers_match_round_and_ema_rules() {
    assert_eq!(estimate_strategy_cost(4, 0.25, false), 1.0);
    assert_eq!(estimate_strategy_cost(4, 0.25, true), 2.0);
    assert!((calibrated_cost_per_round(1.0, 2.0) - 1.3).abs() < 0.000_001);
    assert_eq!(calibrated_cost_per_round(0.0, 2.0), 2.0);
}

fn workspace_with_recorded_strategy_correction(
) -> (tempfile::TempDir, WorkspaceTarget, StrategyCorrection) {
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
        yield_score: None,
        estimated_rounds: None,
        approved_cost_usd: None,
        actual_cost_usd: None,
        findings_count: None,
        confirmed_count: None,
        result_run_id: None,
        failure: None,
        preflight: StrategyPreflight::ready(),
        resource_risk: StrategyResourceRisk::Low,
        status: StrategyProposalStatus::Proposed,
        source_run_id: Some("run-2".to_string()),
        tool: Some("codeql:scan".to_string()),
        next_input: None,
        scope_proposal_ref: None,
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
    let mut proposal =
        StrategyProposal::new(StrategyPhase::Review, "run semgrep:scan", "fast pass");
    proposal.id = "review-semgrep-scan".to_string();
    proposal
}
