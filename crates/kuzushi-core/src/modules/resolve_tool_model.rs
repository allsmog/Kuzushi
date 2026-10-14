use super::*;

pub(crate) fn resolve_tool_model(
    tool_name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<String> {
    crate::runtime::resolve_explicit_model(
        tool_name,
        string_input_any(input, &["model"]),
        ctx.config.model.as_deref(),
    )
}

pub(crate) fn catalog_module() -> BuiltinModule {
    builtin_module(
        "catalog",
        "Catalog",
        ModuleKind::Governance,
        "List native modules and tools.",
        tools_with_policy(
            read_policy(ToolPhase::Operate, WorkspaceRequirement::Optional),
            vec![
                tool("catalog:modules", "List native modules."),
                tool("catalog:tools", "List native tools."),
            ],
        ),
        vec![],
    )
}

pub(crate) fn config_module() -> BuiltinModule {
    builtin_module(
        "config",
        "Config",
        ModuleKind::Governance,
        "Inspect effective configuration.",
        tools_with_policy(
            read_policy(ToolPhase::Operate, WorkspaceRequirement::Optional),
            vec![tool("config:show", "Show the effective config.").without_phase_result()],
        ),
        vec![],
    )
}

pub(crate) fn module_recommender_module() -> BuiltinModule {
    builtin_module(
        "module-recommender",
        "Module Recommender",
        ModuleKind::Catalog,
        "Recommend next Kuzushi module tools from local repository, attack-surface, threat-model, capability, and finding signals.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Operate,
                RuntimeRequirement::InputAware,
                FindingStoreRequirement::Optional,
            ),
            vec![tool_with_options(
                "module-recommender:recommend",
                "Rank installed module tools for the active workspace without executing them.",
                vec![
                target_option(),
                opt(
                    "maxRecommendations",
                    OptionType::Int,
                    "Maximum recommendations to return.",
                )
                .aliases(&["max_recommendations", "limit"])
                .default(json!(8)),
                opt(
                    "useModelRanking",
                    OptionType::Bool,
                    "Explicitly request one model ranking call from an approved allowance. Default ranking is deterministic.",
                )
                .aliases(&["use_model_ranking", "modelRanking"])
                .default(json!(false)),
                opt("maxOutputTokens", OptionType::Int, "Requested model output ceiling (1 to 4096 tokens); adapter enforcement may be unavailable.").default(json!(2048)),
                opt("thinkingLevel", OptionType::String, "Selected model reasoning effort; omitted values retain operator runtime configuration.").aliases(&["thinking_level"]),
                ],
            ).without_phase_result().with_allowance_category(AllowanceCategory::Scope)],
        ),
        vec![],
    )
}
