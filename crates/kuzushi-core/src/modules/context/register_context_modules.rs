use super::*;

pub(in crate::modules) fn register_context_modules(registry: &mut ModuleRegistry) {
    registry.register(context_module());
    registry.register(context_lite_module());
}

pub(in crate::modules) fn context_module() -> BuiltinModule {
    builtin_module(
        "context",
        "Context",
        ModuleKind::Intel,
        "Build and persist repository context snapshots for scanner and shell use.",
        vec![tool_with_options(
            "context:build",
            "Build a lightweight native repository context snapshot.",
            vec![
                opt(
                    "sampleLimit",
                    OptionType::Int,
                    "Maximum source files to sample in the context snapshot.",
                )
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
            ],
        )],
        vec![dag("context:build", "context", &[])],
    )
}

pub(in crate::modules) fn context_lite_module() -> BuiltinModule {
    hidden_module(
        "context-lite",
        "Context Lite",
        ModuleKind::Internal,
        "Internal minimal repository context node kept for MVP scan compatibility.",
        vec![],
        vec![dag("context-lite:index", "context", &["context:build"])],
    )
}
