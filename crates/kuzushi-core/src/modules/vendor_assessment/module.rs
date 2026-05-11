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
                    opt(
                        "target",
                        OptionType::String,
                        "Legacy evidence source alias.",
                    )
                    .deprecated_aliases(&["input"])
                    .advanced(),
                    opt("kind", OptionType::String, "Evidence kind.").advanced(),
                    opt("title", OptionType::String, "Evidence title.").advanced(),
                    opt("vendorName", OptionType::String, "Vendor name.")
                        .aliases(&["vendor_name"])
                        .advanced(),
                    opt("productName", OptionType::String, "Product name.")
                        .aliases(&["product_name"])
                        .advanced(),
                    opt("vendor", OptionType::String, "Legacy vendor name alias.").advanced(),
                    opt(
                        "primaryDomain",
                        OptionType::String,
                        "Primary vendor domain.",
                    )
                    .aliases(&["domain", "primary_domain"])
                    .advanced(),
                    opt("useCase", OptionType::String, "Vendor use case.")
                        .aliases(&["use_case"])
                        .advanced(),
                    opt(
                        "dataClasses",
                        OptionType::StringList,
                        "Data classes in scope.",
                    )
                    .aliases(&["data_classes"])
                    .advanced(),
                    opt(
                        "integrations",
                        OptionType::StringList,
                        "Vendor integrations.",
                    )
                    .advanced(),
                    opt("profile", OptionType::String, "Assessment profile.").advanced(),
                ],
            ),
            tool_with_options(
                "vendor-assessment:scope",
                "Set or inspect assessment scope.",
                vec![
                    opt("vendorName", OptionType::String, "Vendor name."),
                    opt("productName", OptionType::String, "Product name.")
                        .aliases(&["product_name"]),
                    opt("vendor", OptionType::String, "Legacy vendor name alias.")
                        .deprecated_aliases(&["vendor_name"])
                        .advanced(),
                    opt(
                        "primaryDomain",
                        OptionType::String,
                        "Primary vendor domain.",
                    )
                    .aliases(&["domain", "primary_domain"])
                    .advanced(),
                    opt("useCase", OptionType::String, "Vendor use case.")
                        .aliases(&["use_case"])
                        .advanced(),
                    opt(
                        "dataClasses",
                        OptionType::StringList,
                        "Data classes in scope.",
                    )
                    .aliases(&["data_classes"])
                    .advanced(),
                    opt(
                        "integrations",
                        OptionType::StringList,
                        "Vendor integrations.",
                    )
                    .advanced(),
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
                vec![
                    model_option(),
                    opt("runId", OptionType::String, "Assessment run id.")
                        .aliases(&["run_id"])
                        .advanced(),
                ],
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
    let handler = vendor_assessment_handler(name)?;
    handler(input, ctx, runtime)
}

type VendorAssessmentHandler = for<'a, 'b> fn(
    Value,
    &'a ToolExecutionContext<'b>,
    Option<&'a dyn AgentRuntime>,
) -> Result<Value>;

fn vendor_assessment_handler(name: &str) -> Result<VendorAssessmentHandler> {
    VENDOR_ASSESSMENT_HANDLERS
        .iter()
        .find_map(|(tool_name, handler)| (*tool_name == name).then_some(*handler))
        .ok_or_else(|| anyhow::anyhow!("unknown vendor-assessment tool {name:?}"))
}

const VENDOR_ASSESSMENT_HANDLERS: &[(&str, VendorAssessmentHandler)] = &[
    ("vendor-assessment:attach", attach_handler),
    ("vendor-assessment:scope", scope_handler),
    ("vendor-assessment:prompts", prompts_handler),
    ("vendor-assessment:assess", assess_tool),
];

fn attach_handler(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    _runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    attach_tool(input, ctx)
}

fn scope_handler(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    _runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    scope_tool(input, ctx)
}

fn prompts_handler(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    _runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    prompts_tool(input, ctx)
}

fn attach_tool(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = root(&input, ctx)?;
    let source = string_input_any(&input, &["source", "path", "url", "target"])
        .context("vendor-assessment:attach requires source, path, url, or target")?;
    vendor_assessment_capability::attach(
        &root,
        vendor_assessment_capability::AttachmentInput {
            source,
            kind: string_input_any(&input, &["kind"]).unwrap_or_else(|| "other".to_string()),
            title: string_input_any(&input, &["title"]),
            scope_update: scope_update_from_input(&input),
        },
    )
}

fn scope_tool(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = root(&input, ctx)?;
    let clear = read_bool_any(&input, &["clear"])?.unwrap_or(false);
    vendor_assessment_capability::scope(&root, scope_update_from_input(&input), clear)
}

fn prompts_tool(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = root(&input, ctx)?;
    let run_id = string_input_any(&input, &["runId", "run_id"]);
    vendor_assessment_capability::prompts(&root, scope_update_from_input(&input), run_id)
}

fn assess_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let root = root(&input, ctx)?;
    vendor_assessment_capability::assess(&root, scope_update_from_input(&input), runtime, || {
        resolve_tool_model("vendor-assessment:assess", &input, ctx)
    })
}

fn root(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    resolve_tool_target(input, ctx)
}

fn scope_update_from_input(input: &Value) -> vendor_assessment_capability::ScopeUpdate {
    vendor_assessment_capability::ScopeUpdate {
        vendor_name: string_input_any(input, &["vendorName", "vendor"]),
        product_name: string_input_any(input, &["productName"]),
        primary_domain: string_input_any(input, &["primaryDomain", "domain"]),
        use_case: string_input_any(input, &["useCase"]),
        profile: string_input_any(input, &["profile"]),
        data_classes: string_array_or_csv_input(input, &["dataClasses"]),
        integrations: string_array_or_csv_input(input, &["integrations"]),
    }
}
