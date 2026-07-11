use super::*;

pub(crate) fn router_module() -> BuiltinModule {
    use crate::agent_router::AgentRole;
    let mut model_specs: Vec<OptionSpec> = AgentRole::all()
        .iter()
        .map(|role| {
            let name = role.option_store_key();
            let description = format!(
                "Override model for the `{}` role. Format: provider:modelId. \
                 Settable from the shell with `setg {} <model>`. Wins over models.toml.",
                role.as_key(),
                name
            );
            opt(&name, OptionType::String, &description)
        })
        .collect();
    model_specs.sort_by(|a, b| a.name.cmp(&b.name));

    builtin_module(
        "router",
        "Agent router",
        ModuleKind::Governance,
        "Per-role model routing. Set MODEL_<ROLE> via `setg` to override models.toml.",
        tools_with_policy(
            read_policy(ToolPhase::Operate, WorkspaceRequirement::Optional),
            vec![tool_with_options(
                "router:show",
                "Show effective per-role model routing.",
                model_specs,
            )],
        ),
        vec![],
    )
}
