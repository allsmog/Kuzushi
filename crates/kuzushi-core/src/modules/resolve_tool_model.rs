use super::*;

pub(crate) fn resolve_tool_model(
    tool_name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<String> {
    string_input_any(input, &["model"])
        .or_else(|| ctx.config.model.clone())
        .with_context(|| {
            format!(
                "{tool_name} requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model"
            )
        })
}

pub(crate) fn catalog_module() -> BuiltinModule {
    builtin_module(
        "catalog",
        "Catalog",
        ModuleKind::Governance,
        "List native modules and tools.",
        vec![
            tool("catalog:modules", "List native modules."),
            tool("catalog:tools", "List native tools."),
        ],
        vec![],
    )
}

pub(crate) fn config_module() -> BuiltinModule {
    builtin_module(
        "config",
        "Config",
        ModuleKind::Governance,
        "Inspect effective configuration.",
        vec![tool("config:show", "Show the effective config.")],
        vec![],
    )
}
