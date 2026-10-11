use super::*;

pub(crate) fn groups_tool() -> ToolDescriptor {
    tool_with_options(
        "findings:groups",
        "Read source-bound duplicate groups while preserving every member's identity and decision.",
        group_options(),
    )
    .with_policy(tool_policy(
        ToolPhase::Review,
        RuntimeRequirement::Never,
        ToolEffect::Read,
        WorkspaceRequirement::Required,
        FindingStoreRequirement::Required,
    ))
    .without_phase_result()
}

fn group_options() -> Vec<OptionSpec> {
    let mut options = vec![
        opt(
            "filter",
            OptionType::String,
            "Finding filter expression, applied before grouping.",
        ),
        opt(
            "runIds",
            OptionType::Json,
            "Selected Scan run references. Omit for the workspace ledger.",
        ),
        opt(
            "groupId",
            OptionType::String,
            "Selected group id; requires its ledger watermark.",
        ),
        opt(
            "expectedRevision",
            OptionType::String,
            "Content revision from the group list. Changed data requires refresh.",
        ),
    ];
    options.extend(page_options());
    options
}

fn page_options() -> Vec<OptionSpec> {
    vec![
        opt("offset", OptionType::Int, "Group or member page offset.")
            .default(json!(0))
            .advanced(),
        opt(
            "limit",
            OptionType::Int,
            "Groups or members per page, 1 to 200.",
        )
        .default(json!(50)),
    ]
}

pub(in crate::modules) fn execute(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let request: crate::findings::FindingGroupsRequest =
        serde_json::from_value(input.clone()).context("Invalid group request")?;
    let workspace = ctx
        .workspace
        .context("Finding groups require a workspace")?;
    let store = ctx
        .findings_store
        .context("Finding groups require the ledger")?;
    let page =
        crate::findings::read_finding_groups_cancellable(store, workspace, &request, || {
            ctx.ensure_active()
        })?;
    Ok(
        json!({"ok":true,"output":format!("{} groups from {} findings; member decisions remain independent",page.total_groups,page.total_findings),"data":page}),
    )
}

#[cfg(test)]
mod tests;
