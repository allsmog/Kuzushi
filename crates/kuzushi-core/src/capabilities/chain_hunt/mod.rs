//! Model-backed attack-chain composition over confirmed findings.
//!
//! `triage:chain-hunt` is the triage-phase counterpart of the deterministic
//! `findings:chains` fold: a red-team composer reads the confirmed findings
//! ledger and proposes chains of two or more findings where one enables or
//! escalates another, with an ordered attack path, cumulative impact, and
//! detection-difficulty narrative. Every proposed chain is validated against
//! the real fingerprints (hallucinated members are dropped) and persisted as
//! an ordinary open finding (tool `chains`, rule `chains/model`) so the next
//! `triage:run` verdicts the chain itself.

mod chain_finding;
mod hunt_prompt;
mod hunt_result;
mod validate;

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::findings::{Finding, Severity};
use crate::modules::ToolExecutionContext;
use crate::runtime::AgentRuntime;
use crate::structured_output::CostedStructuredJson;

const DEFAULT_MAX_CHAINS: usize = 8;

pub fn execute_triage_chain_hunt(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let runtime = runtime.context(
        "triage:chain-hunt requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "triage:chain-hunt",
        ))?;
    let store = ctx
        .findings_store
        .context("triage:chain-hunt requires the findings store")?;
    let confirmed = super::chains::confirmed_findings(store)?;
    if confirmed.len() < 2 {
        return Ok(hunt_result::empty_chain_hunt_result(confirmed.len()));
    }
    let prior = prior_chain_findings(store)?;
    let max_chains = max_chains_from_input(&input)?;
    let model = resolve_chain_hunt_model(&input, ctx)?;
    let request = hunt_prompt::chain_hunt_request(&model, workspace.root(), &confirmed, &prior);
    let by_fingerprint = fingerprint_index(&confirmed);
    let hunted = hunt_prompt::query_chain_hunt(runtime, request, max_chains, &by_fingerprint)?;
    let persisted = persist_chain_findings(&hunted, ctx, workspace)?;
    Ok(hunt_result::chain_hunt_result(
        &hunted,
        persisted,
        confirmed.len(),
    ))
}

/// A member-resolved model proposal: every member resolved to a real
/// confirmed finding.
struct ModelChain {
    title: String,
    members: Vec<MemberRef>,
    attack_path: Vec<String>,
    cumulative_impact: String,
    why_this_chain_matters: String,
    detection_difficulty: String,
}

struct MemberRef {
    fingerprint: String,
    title: String,
    file_path: String,
    start_line: u32,
    severity: Severity,
}

struct HuntedChains {
    chains: Vec<ModelChain>,
    dropped: usize,
}

fn resolve_chain_hunt_model(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<String> {
    crate::runtime::resolve_explicit_model(
        "triage:chain-hunt",
        input
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string),
        ctx.config.model.as_deref(),
    )
}

fn fingerprint_index(confirmed: &[Finding]) -> BTreeMap<&str, &Finding> {
    confirmed
        .iter()
        .map(|finding| (finding.fingerprint.as_str(), finding))
        .collect()
}

fn persist_chain_findings(
    hunted: &CostedStructuredJson<HuntedChains>,
    ctx: &ToolExecutionContext<'_>,
    workspace: &crate::workspace::WorkspaceTarget,
) -> Result<Option<crate::findings::GenericPersistedRun>> {
    let findings: Vec<Finding> = hunted
        .value
        .chains
        .iter()
        .map(chain_finding::model_chain_finding)
        .collect();
    crate::findings::persist_tool_findings(
        ctx.finding_run_id(),
        workspace.root(),
        &findings,
        ctx.workspace,
        ctx.findings_store,
    )
}

fn prior_chain_findings(store: &crate::findings::FindingStore) -> Result<Vec<Finding>> {
    Ok(store
        .list_all_findings()?
        .into_iter()
        .filter(|finding| finding.tool.trim().eq_ignore_ascii_case("chains"))
        .collect())
}

fn max_chains_from_input(input: &Value) -> Result<usize> {
    let Some(value) = input.get("maxChains") else {
        return Ok(DEFAULT_MAX_CHAINS);
    };
    let max = value
        .as_u64()
        .context("triage:chain-hunt: maxChains must be a positive integer")?;
    anyhow::ensure!(max > 0, "triage:chain-hunt: maxChains must be positive");
    Ok(max as usize)
}
