use super::*;

pub(crate) fn threat_model_module() -> BuiltinModule {
    builtin_module(
        "threat-model",
        "Threat Model",
        ModuleKind::Intel,
        "Build and read threat-model artifacts and methodology overlays.",
        threat_model_tools(),
        vec![dag(
            "threat-model:build",
            "threat-model",
            &["context:build"],
        )],
    )
}

fn threat_model_tools() -> Vec<ToolDescriptor> {
    vec![
        threat_model_build_tool(),
        tool_with_options(
                "threat-model:read",
                "Read the current threat model artifact.",
                threat_model_read_options(),
            )
            .with_policy(tool_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                ToolEffect::Read,
                WorkspaceRequirement::Required,
                FindingStoreRequirement::Optional,
            )),
        tool(
                "threat-model:methodologies",
                "List supported threat-model methodologies.",
            )
            .with_policy(read_policy(
                ToolPhase::Map,
                WorkspaceRequirement::Optional,
            )),
    ]
}

fn threat_model_build_tool() -> ToolDescriptor {
    tool_with_options(
        "threat-model:build",
        "Build a threat model for the current target.",
        threat_model_build_options(),
    )
    .with_prompt(editable_prompt(
        "threat-model guidance",
        "threat-model",
        "build",
        "THREAT_MODEL_PROMPT",
        crate::capabilities::threat_model::DEFAULT_THREAT_MODEL_GUIDANCE.to_string(),
    ))
    .with_policy(workspace_policy(
        ToolPhase::Map,
        RuntimeRequirement::InputAware,
        FindingStoreRequirement::Optional,
    ))
}

fn threat_model_build_options() -> Vec<OptionSpec> {
    let mut options = vec![
        target_option(),
        threat_model_methodology_option("stride"),
        opt("sources", OptionType::StringList, "Parent artifacts for the model.")
            .aliases(&["sourceArtifacts", "source_artifacts"])
            .default(json!(["context", "threat-model"])),
        opt("seed", OptionType::StringList, "Inline or workspace-file seed context.")
            .inline_or_workspace_files(),
        opt("designDoc", OptionType::Path, "Architecture document source.")
            .aliases(&["design_doc", "design"])
            .workspace_read(),
        opt("outputDir", OptionType::Path, "Normalized artifact directory.")
            .aliases(&["output_dir"])
            .state_write()
            .advanced(),
    ];
    options.extend(threat_model_generation_options());
    options.push(model_option());
    options
}

fn threat_model_generation_options() -> Vec<OptionSpec> {
    vec![
        opt("slice", OptionType::Enum, "Threat-model slice to generate.")
            .choices(&["all", "dfd", "stride", "stories", "scope", "scenarios"])
            .default(json!("all"))
            .advanced(),
        opt("stages", OptionType::StringList, "PASTA stages to generate.").advanced(),
        opt("contextMode", OptionType::Enum, "Context snapshot behavior.")
            .aliases(&["context_mode"])
            .choices(&["auto", "refresh", "require", "off"])
            .default(json!("auto"))
            .advanced(),
        int_option("contextLimit", &["contextSampleLimit", "context_sample_limit", "sampleLimit"], 200),
        int_option("maxSourceBytes", &["max_source_bytes"], 200000),
        int_option("maxElements", &["max_elements"], 40),
        int_option("maxThreats", &["max_threats"], 30),
        bool_option("emitFindings", &["emit_findings"], false),
        bool_option("preserveUserEdits", &["preserve_user_edits"], true),
        opt("THREAT_MODEL_PROMPT", OptionType::String, "Prompt guidance or workspace file.")
            .inline_or_workspace_file()
            .advanced(),
    ]
}

fn threat_model_read_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        opt("outputDir", OptionType::Path, "Threat-model artifact directory.")
            .aliases(&["output_dir"])
            .workspace_read()
            .required(),
        threat_model_methodology_option("pasta"),
    ]
}

fn threat_model_methodology_option(default: &str) -> OptionSpec {
    opt("methodology", OptionType::Enum, "Threat-model methodology.")
        .aliases(&["type"])
        .choices(&["pasta", "stride", "dread"])
        .default(json!(default))
}

fn int_option(name: &str, aliases: &[&str], default: i64) -> OptionSpec {
    opt(name, OptionType::Int, "Threat-model generation limit.")
        .aliases(aliases)
        .default(json!(default))
        .advanced()
}

fn bool_option(name: &str, aliases: &[&str], default: bool) -> OptionSpec {
    opt(name, OptionType::Bool, "Threat-model generation policy.")
        .aliases(aliases)
        .default(json!(default))
        .advanced()
}

pub(crate) fn x_ray_module() -> BuiltinModule {
    builtin_module(
        "x-ray",
        "X-Ray",
        ModuleKind::Intel,
        "Repository architecture review that maps entry points, invariants, attack surface, and risk verdicts.",
        x_ray_tools(),
        vec![dag("x-ray:x-ray", "report", &["context:build"])],
    )
}

fn x_ray_tools() -> Vec<ToolDescriptor> {
    let write_policy = target_write_policy(
        ToolPhase::Map,
        RuntimeRequirement::Always,
        FindingStoreRequirement::Optional,
    );
    vec![
        x_ray_run_tool(write_policy, false),
        x_ray_run_tool(write_policy, true),
        tool(
                "x-ray:read",
                "Read the latest repository architecture and attack-surface report.",
            )
            .with_policy(tool_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                ToolEffect::Read,
                WorkspaceRequirement::Required,
                FindingStoreRequirement::Optional,
            )),
    ]
}

fn x_ray_run_tool(policy: ToolPolicy, alias: bool) -> ToolDescriptor {
    let descriptor = if alias {
        hidden_tool_with_options("x-ray:x-ray", "Compatibility alias for x-ray:run.", x_ray_options())
    } else {
        tool_with_options(
            "x-ray:run",
            "Analyze repository structure, entry points, invariants, and attack surface; persist the report artifact.",
            x_ray_options(),
        )
    };
    descriptor
        .with_prompt(editable_prompt(
            "x-ray instructions",
            "x-ray",
            "run",
            "X_RAY_PROMPT",
            crate::capabilities::x_ray::x_ray_system_prompt(),
        ))
        .with_policy(policy)
}

fn x_ray_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        model_option(),
        opt(
            "X_RAY_PROMPT",
            OptionType::String,
            "System prompt text or workspace-file override for X-Ray.",
        )
        .inline_or_workspace_file()
        .advanced(),
        opt(
            "effort",
            OptionType::String,
            "Runtime reasoning effort hint.",
        )
        .advanced(),
        opt(
            "maxBudgetUsd",
            OptionType::Float,
            "Maximum runtime budget for the X-Ray request.",
        )
        .aliases(&["max_budget_usd"])
        .advanced(),
    ]
}

pub(crate) fn dep_hygiene_module() -> BuiltinModule {
    builtin_module(
        "dep-hygiene",
        "Dependency Hygiene",
        ModuleKind::Defense,
        "Check dependency manifests for stale, vulnerable, or policy-risky packages.",
        tools_with_policy(workspace_policy(ToolPhase::Scan, RuntimeRequirement::Never, FindingStoreRequirement::Required), vec![tool_with_options(
            "dep-hygiene:check",
            "Inspect dependency manifests for stale versions, known-vulnerability signals, and supply-chain policy risks.",
            vec![target_option()],
        )]),
        vec![dag("dep-hygiene:check", "findings", &["context:build"])],
    )
}

pub(crate) fn secret_scan_module() -> BuiltinModule {
    builtin_module(
        "secret-scan",
        "Secret Scan",
        ModuleKind::Defense,
        "Fast deterministic secret scanner over source files.",
        tools_with_policy(workspace_policy(ToolPhase::Scan, RuntimeRequirement::Never, FindingStoreRequirement::Required), vec![tool_with_options(
            "secret-scan:scan",
            "Scan source files for high-confidence secrets.",
            vec![
                target_option(),
                opt(
                    "maxFileBytes",
                    OptionType::Int,
                    "Maximum file size to scan.",
                )
                .aliases(&["max_file_bytes"])
                .integer_range(1024, crate::secret_scan::MAX_SUPPORTED_FILE_BYTES as i64)
                .default(json!(524288)),
                max_findings_option(1000).integer_range(1, 10_000),
            ],
        )]),
        vec![dag("secret-scan:scan", "findings", &["context:build"])],
    )
}
