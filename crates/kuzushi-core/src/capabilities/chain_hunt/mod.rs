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
mod inputs;
mod validate;

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::findings::{Finding, Severity};
use crate::modules::ToolExecutionContext;
use crate::runtime::AgentRuntime;
use crate::structured_output::CostedStructuredJson;

pub fn execute_triage_chain_hunt(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    ctx.ensure_active()?;
    let (workspace, store) = relationship_handles(ctx)?;
    let limits = inputs::ChainHuntLimits::from_input(&input)?;
    let inputs = inputs::relationship_inputs(store, &limits)?;
    let confirmed = &inputs.confirmed;
    if confirmed.len() < 2 {
        return Ok(hunt_result::empty_chain_hunt_result(confirmed.len()));
    }
    let runtime = runtime.context("triage:chain-hunt requires an agent runtime")?;
    let model = resolve_chain_hunt_model(&input, ctx)?;
    let request = hunt_prompt::chain_hunt_request(
        &model,
        workspace.root(),
        confirmed,
        &inputs.prior,
        &limits,
    )?;
    let by_fingerprint = fingerprint_index(confirmed);
    let hunted =
        hunt_prompt::query_chain_hunt(runtime, request, limits.max_chains, &by_fingerprint)?;
    ctx.ensure_active()?;
    inputs::ensure_members_still_confirmed(store, &hunted.value.chains)?;
    let persisted = persist_chain_findings(&hunted, ctx, workspace)?;
    Ok(hunt_result::chain_hunt_result(
        &hunted,
        persisted,
        confirmed.len(),
        &inputs.coverage,
    ))
}

fn relationship_handles<'a>(
    ctx: &'a ToolExecutionContext<'_>,
) -> Result<(
    &'a crate::WorkspaceTarget,
    &'a crate::findings::FindingStore,
)> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "triage:chain-hunt",
        ))?;
    let store = ctx
        .findings_store
        .context("triage:chain-hunt requires the findings store")?;
    Ok((workspace, store))
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
    finding_id: Option<i64>,
    scan_id: Option<String>,
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
    crate::findings::persist_tool_findings(ctx, workspace.root(), &findings)
}
