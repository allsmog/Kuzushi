use super::pr_comment::{load_pr_comment_input, pr_comment_chains_from_value};
use kuzushi_core::{
    run_dir, write_run_summary, PrCommentPhaseCost, RunLlmCallAudit, RunSummary, WorkspaceTarget,
};
use serde_json::json;
use std::time::Duration;

#[test]
fn pr_comment_chains_from_result_value_reads_anchored_steps() {
    let chains = pr_comment_chains_from_value(&chain_result_value());

    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].id, "chain-1");
    assert_eq!(chains[0].title, "Auth bypass");
    assert_eq!(chains[0].severity, "critical");
    assert_eq!(chains[0].steps[0].file_path, "src/auth.rs");
    assert_eq!(chains[0].steps[0].start_line, 42);
}

#[test]
fn load_pr_comment_input_reads_run_metadata_footer_fields() {
    let (_tmp, workspace) = workspace_with_summary(&summary_with_metadata("run-pr"));
    write_chain_result(&workspace, "run-pr");
    let input = pr_comment_input_for_run(&workspace, "run-pr", None, None);

    assert_eq!(input.cost_usd, 1.25);
    assert_eq!(input.elapsed, Some(Duration::from_secs(5)));
    assert_eq!(input.kuzushi_version.as_deref(), Some("0.24.0-test"));
    assert_eq!(input.model.as_deref(), Some("openai:gpt-test"));
    assert_eq!(input.git_sha.as_deref(), Some("abcdef123456"));
    assert_eq!(input.phase_costs, expected_phase_costs());
    assert_eq!(input.chains.len(), 1);
    assert_eq!(input.chains[0].id, "chain-1");
}

#[test]
fn load_pr_comment_input_prefers_explicit_model_and_git_flags() {
    let (_tmp, workspace) = workspace_with_summary(&summary_with_metadata("run-flags"));
    let input = pr_comment_input_for_run(
        &workspace,
        "run-flags",
        Some("openai:from-flag"),
        Some("flagsha"),
    );

    assert_eq!(input.model.as_deref(), Some("openai:from-flag"));
    assert_eq!(input.git_sha.as_deref(), Some("flagsha"));
}

fn chain_result_value() -> serde_json::Value {
    json!({
        "data": {
            "chains": [{
                "id": "chain-1",
                "name": "Auth bypass",
                "overallSeverity": "critical",
                "steps": [{
                    "role": "source",
                    "description": "Untrusted request data",
                    "filePath": "src/auth.rs",
                    "startLine": 42
                }]
            }]
        }
    })
}

fn workspace_with_summary(summary: &RunSummary) -> (tempfile::TempDir, WorkspaceTarget) {
    let tmp = tempfile::tempdir().unwrap();
    write_run_summary(tmp.path(), summary).unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    (tmp, workspace)
}

fn write_chain_result(workspace: &WorkspaceTarget, run_id: &str) {
    let dir = run_dir(workspace.root(), run_id);
    std::fs::create_dir_all(&dir).unwrap();
    let leaf = kuzushi_core::tool_result_artifact_spec("result.json")
        .expect("tool result artifact must be in shared spec")
        .leaf;
    std::fs::write(dir.join(leaf), chain_result_value().to_string()).unwrap();
}

fn pr_comment_input_for_run(
    workspace: &WorkspaceTarget,
    run_id: &str,
    model: Option<&str>,
    git_sha: Option<&str>,
) -> kuzushi_core::PrCommentInput {
    load_pr_comment_input(
        workspace,
        None,
        None,
        5,
        Vec::new(),
        Some(run_id.to_string()),
        model.map(str::to_string),
        git_sha.map(str::to_string),
    )
    .unwrap()
}

fn summary_with_metadata(run_id: &str) -> RunSummary {
    let mut summary = RunSummary::running(run_id, "scan", Some("triage:run".to_string()), "/repo")
        .with_cost(Some(1.25))
        .with_llm_calls(vec![
            llm_call(1, Some("triage"), 0.75),
            llm_call(2, Some("verify"), 0.50),
        ]);
    summary.started_at_unix = 10;
    summary.completed_at_unix = Some(15);
    summary.kuzushi_version = Some("0.24.0-test".to_string());
    summary.model = Some("openai:gpt-test".to_string());
    summary.git_sha = Some("abcdef123456".to_string());
    summary
}

fn llm_call(n: usize, verb: Option<&str>, cost_usd: f64) -> RunLlmCallAudit {
    RunLlmCallAudit {
        n,
        kind: "reasoning".to_string(),
        verb: verb.map(str::to_string),
        model: "openai:gpt-test".to_string(),
        provider: "openai".to_string(),
        prompt_hash: format!("sha256:{n}"),
        latency_ms: None,
        cost_usd: Some(cost_usd),
    }
}

fn expected_phase_costs() -> Vec<PrCommentPhaseCost> {
    vec![
        PrCommentPhaseCost {
            label: "triage".to_string(),
            cost_usd: 0.75,
        },
        PrCommentPhaseCost {
            label: "verify".to_string(),
            cost_usd: 0.50,
        },
    ]
}
