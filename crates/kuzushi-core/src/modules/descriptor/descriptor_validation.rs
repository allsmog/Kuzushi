use super::{
    ApprovalPolicy, FindingStoreRequirement, ToolDescriptor, WorkspaceRequirement,
};
use anyhow::Result;

pub(in crate::modules) fn validate_declared_policy(
    tool: &ToolDescriptor,
    module_id: &str,
) -> Result<()> {
    if !tool.policy_declared {
        anyhow::bail!(
            "built-in tool {:?} in module {:?} has no descriptor-owned policy",
            tool.name,
            module_id
        )
    }
    if tool.effect.needs_operator_approval() && tool.approval != ApprovalPolicy::Explicit {
        anyhow::bail!(
            "built-in tool {:?} has {:?} effect without explicit approval",
            tool.name,
            tool.effect
        )
    }
    if tool.finding_store_requirement == FindingStoreRequirement::Required
        && tool.workspace_requirement != WorkspaceRequirement::Required
    {
        anyhow::bail!(
            "built-in tool {:?} requires a finding store but not a workspace",
            tool.name
        )
    }
    validate_prompt_options(tool, "built-in tool")
}

pub(in crate::modules) fn validate_prompt_options(
    tool: &ToolDescriptor,
    kind: &str,
) -> Result<()> {
    for prompt in &tool.prompts {
        if !tool
            .options
            .iter()
            .any(|option| option.name == prompt.option_key)
        {
            anyhow::bail!(
                "{kind} {:?} prompt {:?} refers to undeclared option {:?}",
                tool.name,
                prompt.role,
                prompt.option_key
            )
        }
    }
    Ok(())
}
