use anyhow::Result;
use kuzushi_core::runtime::RuntimeCost;
use kuzushi_core::{
    build_pr_comment, load_run_summary, read_run_artifact_text, tool_result_artifact_spec,
    FindingListFilter, FindingStore, PrCommentChain, PrCommentChainStep, PrCommentInput,
    PrCommentPhaseCost, RunArtifactRead, RunLlmCallAudit, RunSummary, WorkspaceTarget,
};
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

pub(crate) fn pr_comment_command(
    target: PathBuf,
    repo: Option<String>,
    run_url: Option<String>,
    top_n: usize,
    changed_files: Vec<String>,
    run_id: Option<String>,
    model: Option<String>,
    git_sha: Option<String>,
) -> Result<()> {
    let workspace = WorkspaceTarget::new(target)?;
    let input = load_pr_comment_input(
        &workspace,
        repo,
        run_url,
        top_n,
        changed_files,
        run_id,
        model,
        git_sha,
    )?;
    println!("{}", build_pr_comment(&input));
    Ok(())
}

pub(crate) fn load_pr_comment_input(
    workspace: &WorkspaceTarget,
    repo: Option<String>,
    run_url: Option<String>,
    top_n: usize,
    changed_files: Vec<String>,
    run_id: Option<String>,
    model: Option<String>,
    git_sha: Option<String>,
) -> Result<PrCommentInput> {
    let store = FindingStore::open(workspace.findings_db_path())?;
    let report = store.list_findings_filtered(&FindingListFilter::default())?;
    let metadata = load_pr_comment_run_metadata(workspace, run_id.as_deref());
    let chains = load_pr_comment_chains(workspace, run_id.as_deref());
    Ok(PrCommentInput {
        repo_name: repo.or_else(|| {
            workspace
                .root()
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
        }),
        findings: report.findings,
        cost_usd: metadata.cost_usd.unwrap_or(0.0),
        provider_spend_unresolved: metadata.provider_spend_unresolved,
        phase_costs: metadata.phase_costs,
        elapsed: metadata.elapsed,
        chains,
        run_url,
        top_n: Some(top_n),
        kuzushi_version: metadata
            .kuzushi_version
            .or_else(|| Some(env!("CARGO_PKG_VERSION").to_string())),
        model: model.or(metadata.model),
        git_sha: git_sha.or(metadata.git_sha),
        run_id,
        changed_files,
    })
}

#[derive(Default)]
struct PrCommentRunMetadata {
    cost_usd: Option<f64>,
    provider_spend_unresolved: bool,
    elapsed: Option<Duration>,
    phase_costs: Vec<PrCommentPhaseCost>,
    kuzushi_version: Option<String>,
    model: Option<String>,
    git_sha: Option<String>,
}

fn load_pr_comment_run_metadata(
    workspace: &WorkspaceTarget,
    run_id: Option<&str>,
) -> PrCommentRunMetadata {
    let Some(run_id) = run_id.filter(|id| !id.trim().is_empty()) else {
        return PrCommentRunMetadata::default();
    };
    load_run_summary(workspace.root(), run_id)
        .map(|summary| pr_comment_run_metadata(&summary))
        .unwrap_or_else(|_| PrCommentRunMetadata {
            provider_spend_unresolved: true,
            ..Default::default()
        })
}

fn pr_comment_run_metadata(summary: &RunSummary) -> PrCommentRunMetadata {
    let cost_report = summary.checked_cost_report();
    let total_cost = cost_report
        .as_ref()
        .ok()
        .and_then(|cost| cost.observed_usd_if_available());
    let phase_costs = phase_costs_from_llm_calls(&summary.llm_calls);
    let provider_spend_unresolved = match cost_report.as_ref() {
        Ok(cost) => !cost.is_complete(),
        Err(_) => true,
    } || phase_costs.is_err();
    PrCommentRunMetadata {
        cost_usd: total_cost,
        provider_spend_unresolved,
        elapsed: summary_elapsed(summary),
        phase_costs: phase_costs.unwrap_or_default(),
        kuzushi_version: summary.kuzushi_version.clone(),
        model: summary.model.clone(),
        git_sha: summary.git_sha.clone(),
    }
}

fn phase_costs_from_llm_calls(calls: &[RunLlmCallAudit]) -> Result<Vec<PrCommentPhaseCost>> {
    let mut by_phase = BTreeMap::<String, RuntimeCost>::new();
    for call in calls {
        add_phase_cost(&mut by_phase, call)?;
    }
    Ok(by_phase
        .into_iter()
        .map(|(label, cost)| PrCommentPhaseCost {
            label,
            cost_usd: cost.usd(),
        })
        .collect())
}

fn add_phase_cost(
    by_phase: &mut BTreeMap<String, RuntimeCost>,
    call: &RunLlmCallAudit,
) -> Result<()> {
    let Some(cost) = call.cost_usd else {
        return Ok(());
    };
    let cost = RuntimeCost::from_usd(cost, "PR comment phase cost")?;
    if cost == RuntimeCost::ZERO {
        return Ok(());
    }
    let phase = call
        .verb
        .as_deref()
        .filter(|verb| !verb.trim().is_empty())
        .unwrap_or(&call.kind)
        .to_string();
    let previous = by_phase.get(&phase).copied().unwrap_or(RuntimeCost::ZERO);
    by_phase.insert(phase, previous.checked_add(cost, "PR comment phase cost")?);
    Ok(())
}

fn summary_elapsed(summary: &RunSummary) -> Option<Duration> {
    let completed = summary.completed_at_unix?;
    completed
        .checked_sub(summary.started_at_unix)
        .map(Duration::from_secs)
}

fn load_pr_comment_chains(
    workspace: &WorkspaceTarget,
    run_id: Option<&str>,
) -> Vec<PrCommentChain> {
    let Some(run_id) = run_id.filter(|id| !id.trim().is_empty()) else {
        return Vec::new();
    };
    let RunArtifactRead::Ready { value: body, .. } =
        read_run_artifact_text(workspace.root(), run_id, result_artifact_leaf())
    else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(&body) else {
        return Vec::new();
    };
    pr_comment_chains_from_value(&value)
}

fn result_artifact_leaf() -> &'static str {
    tool_result_artifact_spec("result.json")
        .expect("tool result artifact must be in shared spec")
        .leaf
}

pub(super) fn pr_comment_chains_from_value(value: &Value) -> Vec<PrCommentChain> {
    chain_array(value)
        .map(|chains| {
            chains
                .iter()
                .filter_map(pr_comment_chain_from_value)
                .collect()
        })
        .unwrap_or_default()
}

fn chain_array(value: &Value) -> Option<&Vec<Value>> {
    value
        .pointer("/data/chains")
        .or_else(|| value.get("chains"))
        .and_then(Value::as_array)
}

fn pr_comment_chain_from_value(value: &Value) -> Option<PrCommentChain> {
    let steps = value
        .get("steps")
        .and_then(Value::as_array)
        .map(|steps| chain_steps_from_values(steps))
        .unwrap_or_default();
    Some(PrCommentChain {
        id: string_field(value, "id")?,
        title: string_field(value, "name")?,
        severity: string_field(value, "overallSeverity").unwrap_or_else(|| "unknown".to_string()),
        steps,
    })
}

fn chain_steps_from_values(values: &[Value]) -> Vec<PrCommentChainStep> {
    values.iter().filter_map(chain_step_from_value).collect()
}

fn chain_step_from_value(value: &Value) -> Option<PrCommentChainStep> {
    Some(PrCommentChainStep {
        role: string_field(value, "role")?,
        description: string_field(value, "description")?,
        file_path: string_field(value, "filePath")?,
        start_line: value
            .get("startLine")
            .and_then(Value::as_u64)
            .and_then(|line| u32::try_from(line).ok())
            .unwrap_or(1),
    })
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(Value::as_str).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_costs_use_checked_aggregation() {
        let costs = phase_costs_from_llm_calls(&[
            llm_call("triage", Some(0.1)),
            llm_call("triage", Some(0.2)),
        ])
        .unwrap();

        assert_eq!(costs.len(), 1);
        assert!((costs[0].cost_usd - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn phase_costs_reject_invalid_values_and_overflow() {
        for invalid in [f64::NAN, -1.0, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(phase_costs_from_llm_calls(&[llm_call("triage", Some(invalid))]).is_err());
        }
        assert!(phase_costs_from_llm_calls(&[
            llm_call("triage", Some(f64::MAX)),
            llm_call("triage", Some(f64::MAX)),
        ])
        .is_err());
    }

    fn llm_call(kind: &str, cost_usd: Option<f64>) -> RunLlmCallAudit {
        RunLlmCallAudit {
            n: 1,
            kind: kind.to_string(),
            verb: None,
            model: "test:model".to_string(),
            provider: "test".to_string(),
            prompt_hash: "sha256:test".to_string(),
            latency_ms: Some(1),
            cost_usd,
            observed_cost_usd: None,
            provider_spend_unresolved: false,
            call_attempted: Some(true),
        }
    }
}
