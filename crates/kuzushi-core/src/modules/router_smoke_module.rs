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
        vec![tool_with_options(
            "router:show",
            "Show effective per-role model routing.",
            model_specs,
        )],
        vec![],
    )
}

pub(crate) fn smoke_module() -> BuiltinModule {
    builtin_module(
        "smoke",
        "Smoke tests",
        ModuleKind::Governance,
        "Diagnostic flows that exercise the bridge end-to-end without paying for a real scan.",
        vec![tool_with_options(
            "smoke:next-step",
            "Drive a 2-step tool-loop with an `echo` tool to verify next_step_blocking + run_tool_loop.",
            vec![opt(
                "phrase",
                OptionType::String,
                "Phrase the model is asked to echo back. Default: 'kuzushi-ok'.",
            )
            .default(serde_json::json!("kuzushi-ok"))],
        )],
        vec![],
    )
}
