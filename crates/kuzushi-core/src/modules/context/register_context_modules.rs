use super::*;

use crate::modules::registry::ToolExecutor;

pub(in crate::modules) fn register_context_modules(
    registry: &mut ModuleRegistry,
    executor: ToolExecutor,
) {
    registry.register(context_module().with_executor(executor));
    registry.register(context_lite_module().with_executor(executor));
}

pub(in crate::modules) fn context_module() -> BuiltinModule {
    builtin_module(
        "context",
        "Context",
        ModuleKind::Intel,
        "Build and persist repository context snapshots for scanner and shell use.",
        vec![context_build_tool()],
        vec![dag("context:build", "context", &[])],
    )
}

fn context_build_tool() -> ToolDescriptor {
    tool_with_options(
        "context:build",
        "Build a lightweight native repository context snapshot.",
        context_options(),
    )
    .with_policy(workspace_policy(
        ToolPhase::Map,
        RuntimeRequirement::Never,
        FindingStoreRequirement::Optional,
    ))
}

fn context_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "sampleLimit",
            OptionType::Int,
            "Maximum source files to sample in the context snapshot.",
        )
        .aliases(&["limit", "sample_limit"])
        .default(json!(200)),
        opt("discovery", OptionType::Enum, "Repository discovery mode.")
            .choices(&["auto", "flat", "modules"])
            .default(json!("auto")),
        opt(
            "enrichment",
            OptionType::Bool,
            "Request LLM-backed context enrichment when supported.",
        )
        .default(json!(false))
        .advanced(),
        opt("scope", OptionType::Enum, "Context slice to build.")
            .choices(&["all", "repo", "enrichment", "app-model"])
            .default(json!("all")),
    ]
}

pub(in crate::modules) fn context_lite_module() -> BuiltinModule {
    hidden_module(
        "context-lite",
        "Context Lite",
        ModuleKind::Internal,
        "Internal minimal repository context node kept for MVP scan compatibility.",
        vec![hidden_tool_with_options(
            "context-lite:index",
            "Build the internal minimal repository context snapshot.",
            context_options(),
        )
        .with_policy(workspace_policy(
            ToolPhase::Map,
            RuntimeRequirement::Never,
            FindingStoreRequirement::Optional,
        ))],
        vec![dag("context-lite:index", "context", &["context:build"])],
    )
}
