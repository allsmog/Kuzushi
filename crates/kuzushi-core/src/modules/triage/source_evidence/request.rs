use super::*;
use std::collections::BTreeMap;

pub(in crate::modules::triage) fn load_for_execution(
    input: &Value,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
    source_tree: &str,
) -> Result<BTreeMap<i64, String>> {
    if !validate_policy(input)? {
        return Ok(BTreeMap::new());
    }
    let workspace = ctx
        .workspace
        .context("Review source evidence requires a workspace")?;
    let document = inspect(workspace.root(), input, findings)?
        .context("Prepare cited source evidence with campaign:review-study before model work")?;
    anyhow::ensure!(
        source_tree == document.tree_hash,
        "Frozen Review source changed; prepare and approve a new draft"
    );
    Ok(document
        .observations
        .iter()
        .map(|source| (source.generation_id, source.model_input()))
        .collect())
}

pub(in crate::modules::triage) fn model_note(
    input: &TriageRunInput,
    finding: &Finding,
) -> Option<String> {
    finding
        .id
        .and_then(|id| input.source_evidence.get(&id))
        .cloned()
}
