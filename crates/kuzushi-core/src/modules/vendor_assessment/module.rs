use super::*;

pub(in crate::modules) fn module() -> BuiltinModule {
    builtin_module(
        "vendor-assessment",
        "Vendor Assessment",
        ModuleKind::Governance,
        "Vendor security assessment workspace: attach docs, set scope, generate prompts, assess.",
        vendor_assessment_tools(),
        vec![],
    )
}

fn vendor_assessment_tools() -> Vec<ToolDescriptor> {
    vec![
        vendor_assessment_attach_tool(),
        tool_with_options(
            "vendor-assessment:scope",
            "Set or inspect assessment scope.",
            vendor_assessment_scope_options(),
        ),
        tool_with_options(
            "vendor-assessment:prompts",
            "Generate assessment prompt packets.",
            vendor_assessment_prompt_options(),
        ),
        tool_with_options(
            "vendor-assessment:assess",
            "Run vendor assessment.",
            vendor_assessment_assess_options(),
        ),
    ]
}

fn vendor_assessment_attach_tool() -> ToolDescriptor {
    tool_with_options(
        "vendor-assessment:attach",
        "Attach vendor evidence documents.",
        vendor_assessment_attach_options(),
    )
}

fn vendor_assessment_attach_options() -> Vec<OptionSpec> {
    let mut options = vec![
        opt("source", OptionType::String, "Evidence source path or URL."),
        opt("path", OptionType::Path, "Evidence document path."),
        opt("url", OptionType::String, "Evidence document URL."),
        deprecated_target_option(),
        opt("kind", OptionType::String, "Evidence kind.").advanced(),
        opt("title", OptionType::String, "Evidence title.").advanced(),
    ];
    options.extend(vendor_assessment_attach_metadata_options());
    options
}

fn deprecated_target_option() -> OptionSpec {
    opt(
        "target",
        OptionType::String,
        "Legacy evidence source alias.",
    )
    .deprecated_aliases(&["input"])
    .advanced()
}

fn vendor_assessment_scope_options() -> Vec<OptionSpec> {
    vec![
        vendor_name_option(),
        opt("productName", OptionType::String, "Product name.").aliases(&["product_name"]),
        primary_domain_option(),
        use_case_option(),
        data_classes_option(),
        integrations_option(),
        opt("profile", OptionType::String, "Assessment profile.").default(json!("enterprise-ai")),
    ]
}

fn vendor_name_option() -> OptionSpec {
    opt("vendorName", OptionType::String, "Vendor name.")
        .aliases(&["vendor"])
        .deprecated_aliases(&["vendor_name"])
}

fn vendor_assessment_attach_metadata_options() -> Vec<OptionSpec> {
    vec![
        vendor_name_option().advanced(),
        opt("productName", OptionType::String, "Product name.")
            .aliases(&["product_name"])
            .advanced(),
        primary_domain_option(),
        use_case_option(),
        data_classes_option(),
        integrations_option(),
        opt("profile", OptionType::String, "Assessment profile.").advanced(),
    ]
}

fn primary_domain_option() -> OptionSpec {
    opt(
        "primaryDomain",
        OptionType::String,
        "Primary vendor domain.",
    )
    .aliases(&["domain", "primary_domain"])
    .advanced()
}

fn use_case_option() -> OptionSpec {
    opt("useCase", OptionType::String, "Vendor use case.")
        .aliases(&["use_case"])
        .advanced()
}

fn data_classes_option() -> OptionSpec {
    opt(
        "dataClasses",
        OptionType::StringList,
        "Data classes in scope.",
    )
    .aliases(&["data_classes"])
    .advanced()
}

fn integrations_option() -> OptionSpec {
    opt(
        "integrations",
        OptionType::StringList,
        "Vendor integrations.",
    )
    .advanced()
}

fn vendor_assessment_prompt_options() -> Vec<OptionSpec> {
    let mut options = vendor_assessment_scope_options();
    options.push(vendor_assessment_run_id_option());
    options
}

fn vendor_assessment_assess_options() -> Vec<OptionSpec> {
    let mut options = vec![model_option()];
    options.extend(vendor_assessment_scope_options());
    options.push(vendor_assessment_run_id_option());
    options
}

fn vendor_assessment_run_id_option() -> OptionSpec {
    opt("runId", OptionType::String, "Assessment run id.")
        .aliases(&["run_id"])
        .advanced()
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
    let run_id = string_input_any(&input, &["runId"]);
    vendor_assessment_capability::prompts(&root, scope_update_from_input(&input), run_id)
}

fn assess_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let root = root(&input, ctx)?;
    let parent_step = emit_vendor_assessment_start(ctx, &root);
    emit_vendor_assessment_progress(ctx, parent_step, "scope · load documents and prompts");
    let _assessment_scope = begin_vendor_assessment_scope(ctx, parent_step);
    let result = vendor_assessment_capability::assess(
        &root,
        scope_update_from_input(&input),
        runtime,
        || resolve_tool_model("vendor-assessment:assess", &input, ctx),
    )?;
    drop(_assessment_scope);
    emit_vendor_assessment_progress(ctx, parent_step, "artifacts · write report");
    emit_vendor_assessment_done(ctx, &result);
    Ok(result)
}

fn emit_vendor_assessment_start(ctx: &ToolExecutionContext<'_>, root: &Path) -> Option<usize> {
    ctx.trace.map(|trace| {
        trace
            .step(
                "tool",
                "assess",
                format!("vendor-assessment:assess start · target={}", root.display()),
            )
            .emit()
    })
}

fn emit_vendor_assessment_progress(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    label: impl Into<String>,
) {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return;
    };
    let _ = trace
        .child(parent)
        .step("tool-progress", "assess", label.into())
        .emit();
}

fn begin_vendor_assessment_scope(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
) -> Option<crate::run_artifacts::ParentScope> {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return None;
    };
    let phase = trace
        .child(parent)
        .step("reasoning", "assess", "document review · risk assessment")
        .emit();
    Some(trace.parent_scope(phase))
}

fn emit_vendor_assessment_done(ctx: &ToolExecutionContext<'_>, result: &Value) {
    if let Some(trace) = ctx.trace {
        let risk = result
            .pointer("/data/report/overallRisk")
            .and_then(Value::as_str)
            .unwrap_or("complete");
        let _ = trace
            .step(
                "done",
                "assess",
                format!("vendor-assessment:assess complete · {risk}"),
            )
            .emit();
    }
}

fn root(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    resolve_tool_target(input, ctx)
}

fn scope_update_from_input(input: &Value) -> vendor_assessment_capability::ScopeUpdate {
    vendor_assessment_capability::ScopeUpdate {
        vendor_name: string_input_any(input, &["vendorName"]),
        product_name: string_input_any(input, &["productName"]),
        primary_domain: string_input_any(input, &["primaryDomain"]),
        use_case: string_input_any(input, &["useCase"]),
        profile: string_input_any(input, &["profile"]),
        data_classes: string_array_or_csv_input(input, &["dataClasses"]),
        integrations: string_array_or_csv_input(input, &["integrations"]),
    }
}
