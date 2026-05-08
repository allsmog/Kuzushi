use super::prelude::*;
use super::*;

pub(in crate::modules) fn module() -> BuiltinModule {
    builtin_module(
        "vendor-assessment",
        "Vendor Assessment",
        ModuleKind::Governance,
        "Vendor security assessment workspace: attach docs, set scope, generate prompts, assess.",
        vec![
            tool_with_options(
                "vendor-assessment:attach",
                "Attach vendor evidence documents.",
                vec![
                    opt("source", OptionType::String, "Evidence source path or URL."),
                    opt("path", OptionType::Path, "Evidence document path."),
                    opt("url", OptionType::String, "Evidence document URL."),
                ],
            ),
            tool_with_options(
                "vendor-assessment:scope",
                "Set or inspect assessment scope.",
                vec![
                    opt("vendorName", OptionType::String, "Vendor name."),
                    opt("productName", OptionType::String, "Product name."),
                    opt("profile", OptionType::String, "Assessment profile.")
                        .default(json!("enterprise-ai")),
                ],
            ),
            tool(
                "vendor-assessment:prompts",
                "Generate assessment prompt packets.",
            ),
            tool_with_options(
                "vendor-assessment:assess",
                "Run vendor assessment.",
                vec![model_option()],
            ),
        ],
        vec![],
    )
}

pub(in crate::modules) fn execute_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match name {
        "vendor-assessment:attach" => attach(input, ctx),
        "vendor-assessment:scope" => scope(input, ctx),
        "vendor-assessment:prompts" => prompts(input, ctx),
        "vendor-assessment:assess" => assess(input, ctx, runtime),
        _ => anyhow::bail!("unknown vendor-assessment tool {name:?}"),
    }
}

pub(in crate::modules) fn root(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    resolve_tool_target(input, ctx)
}

pub(in crate::modules) fn scope_path(root: &Path) -> PathBuf {
    root.join(".kuzushi")
        .join("vendor-assessment")
        .join("scope.json")
}

pub(in crate::modules) fn runs_dir(root: &Path) -> PathBuf {
    root.join(".kuzushi").join("vendor-assessment").join("runs")
}

pub(in crate::modules) fn load_scope(root: &Path) -> Result<Value> {
    let path = scope_path(root);
    if !path.exists() {
        return Ok(empty_scope());
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("Could not read vendor assessment scope {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("Could not parse vendor assessment scope {}", path.display()))
}

pub(in crate::modules) fn save_scope(root: &Path, scope: &Value) -> Result<PathBuf> {
    let path = scope_path(root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    fs::write(&path, format!("{}\n", serde_json::to_string_pretty(scope)?))
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}
