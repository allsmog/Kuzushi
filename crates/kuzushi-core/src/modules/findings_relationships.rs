//! Shared read/review tools over reversible relationship metadata.
use super::*;
use crate::findings::FindingRelationshipState;

pub(crate) fn relationship_tools() -> Vec<ToolDescriptor> {
    vec![
        tool_with_options("findings:relationships","List recorded duplicate, related-variant and uncertain relationships without changing findings.",vec![
            opt("findingId",OptionType::Int,"Limit to relationships touching this durable finding id.").aliases(&["finding_id"]),
            opt("limit",OptionType::Int,"Relationships per page, 1 to 200.").default(json!(50)),
            opt("offset",OptionType::Int,"Relationship page offset.").default(json!(0)).advanced(),
        ]).with_policy(tool_policy(ToolPhase::Review,RuntimeRequirement::Never,ToolEffect::Read,WorkspaceRequirement::Required,FindingStoreRequirement::Required)).without_phase_result(),
        tool_with_options("findings:relationship","Review or undo a finding relationship. Finding identities and verdicts remain independent.",vec![
            opt("id",OptionType::String,"Relationship id.").required(),
            opt("state",OptionType::Enum,"Relationship decision.").choices(&["accepted","rejected","removed"]).required(),
            opt("note",OptionType::String,"Required reason for the relationship decision.").required(),
            opt("expectedRevision",OptionType::Int,"Revision shown when the operator reviewed this relationship.").aliases(&["expected_revision"]).required(),
        ]).with_policy(workspace_policy(ToolPhase::Review,RuntimeRequirement::Never,FindingStoreRequirement::Required)).without_phase_result(),
        tool_with_options("findings:relationship-batch","Review a bounded selection atomically. Finding identities and verdicts stay separate.",vec![
            opt("relationships",OptionType::Json,"Exact recorded relationship objects, including revisions, from the reader. Choose 1 to 50.").required(),
            opt("state",OptionType::Enum,"Decision for this reviewed selection.").choices(&["accepted","rejected","removed"]).required(),
            opt("note",OptionType::String,"Required operator reason for the selected decisions.").required(),
        ]).with_policy(workspace_policy(ToolPhase::Review,RuntimeRequirement::Never,FindingStoreRequirement::Required)).without_phase_result(),
    ]
}

pub(in crate::modules) fn execute_finding_relationship_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let store = ctx
        .findings_store
        .context("finding relationships require the findings store")?;
    if name == "findings:relationships" {
        return list_relationships(store, input);
    }
    if name == "findings:relationship-batch" {
        ctx.ensure_active()?;
        return review_batch(store, input);
    }
    review_relationship(store, input)
}

fn review_batch(store: &FindingStore, input: &Value) -> Result<Value> {
    let rows = input["relationships"]
        .as_array()
        .context("relationships must be a recorded array")?;
    anyhow::ensure!(
        (1..=50).contains(&rows.len()),
        "Choose between 1 and 50 relationships"
    );
    let records: Vec<crate::findings::FindingRelationship> =
        serde_json::from_value(input["relationships"].clone())
            .context("relationships must contain exact recorded objects")?;
    let note = string_input_any(input, &["note"]).context("relationship reason is required")?;
    let state = serde_json::from_value(input["state"].clone())?;
    let reviewed = store.review_finding_relationship_batch(&records, state, &note)?;
    Ok(
        json!({"ok":true,"output":format!("{} relationship decisions recorded atomically; finding verdicts stay separate",reviewed.len()),"data":{"schemaVersion":1,"records":reviewed}}),
    )
}

fn list_relationships(store: &FindingStore, input: &Value) -> Result<Value> {
    let finding_id = input.get("findingId").and_then(Value::as_i64);
    let limit = page_count(input, "limit", 50)?;
    let offset = page_count(input, "offset", 0)?;
    let page = store.finding_relationships(finding_id, limit, offset)?;
    Ok(
        json!({"ok":true,"output":format!("{} recorded relationships; finding verdicts are unchanged",page.rows.len()),"data":page}),
    )
}

fn page_count(input: &Value, key: &str, default: usize) -> Result<usize> {
    let Some(value) = input.get(key) else {
        return Ok(default);
    };
    let count = value
        .as_u64()
        .with_context(|| format!("{key} must be a nonnegative integer"))?;
    usize::try_from(count).with_context(|| format!("{key} exceeds the supported range"))
}

fn review_relationship(store: &FindingStore, input: &Value) -> Result<Value> {
    let id = string_input_any(input, &["id"]).context("relationship id is required")?;
    let note = string_input_any(input, &["note"]).context("relationship reason is required")?;
    let revision = input
        .get("expectedRevision")
        .and_then(Value::as_u64)
        .context("expectedRevision must be a nonnegative integer")?;
    let state: FindingRelationshipState = serde_json::from_value(input["state"].clone())?;
    let record = store.review_finding_relationship(&id, state, &note, revision)?;
    Ok(
        json!({"ok":true,"output":"Relationship decision recorded; finding verdicts and observations are unchanged","data":record}),
    )
}

#[cfg(test)]
mod tests;
