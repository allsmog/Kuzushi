use super::*;

pub(crate) fn pipeline_module() -> BuiltinModule {
    hidden_module(
        "pipeline",
        "Pipeline",
        ModuleKind::Internal,
        "Internal orchestrator DAG nodes for task selection, approval gates, and taint sub-tasks.",
        pipeline_tools(),
        vec![
            dag(
                "pipeline:task-selector",
                "task-selection",
                &["context:build"],
            ),
            dag(
                "pipeline:approval-before-verification",
                "approval",
                &["triage:run"],
            ),
            dag(
                "pipeline:taint-cwe-select",
                "cwe-selection",
                &["context:build"],
            ),
        ],
    )
}

fn pipeline_tools() -> Vec<ToolDescriptor> {
    tools_with_policy(
        tool_policy(
            ToolPhase::Hunt,
            RuntimeRequirement::Never,
            ToolEffect::WorkspaceWrite,
            WorkspaceRequirement::Optional,
            FindingStoreRequirement::Optional,
        ),
        vec![
            pipeline_task_selector_tool(),
            pipeline_approval_tool(),
            pipeline_taint_cwe_select_tool(),
        ],
    )
}

fn pipeline_task_selector_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "pipeline:task-selector",
        "Select enabled SAST tasks after applying disabled task filters.",
        vec![
            opt("tasks", OptionType::StringList, "Requested scan task ids.")
                .aliases(&["taskIds", "task_ids"])
                .advanced(),
            opt(
                "disabledTasks",
                OptionType::StringList,
                "Disabled scan task ids.",
            )
            .aliases(&["disabled_tasks"])
            .advanced(),
        ],
    )
}

fn pipeline_approval_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "pipeline:approval-before-verification",
        "Represent the verification approval gate decision.",
        vec![opt(
            "approved",
            OptionType::Bool,
            "Whether verification is approved.",
        )
        .aliases(&["approve"])
        .default(json!(true))],
    )
}

fn pipeline_taint_cwe_select_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "pipeline:taint-cwe-select",
        "Select taint-analysis CWE classes for Taint IRIS.",
        pipeline_taint_cwe_select_options(),
    )
}

fn pipeline_taint_cwe_select_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        opt("cwes", OptionType::Json, "Explicit CWE selection.")
            .aliases(&["cwe"])
            .advanced(),
        opt(
            "whiteboxStatic",
            OptionType::Json,
            "Whitebox static analysis policy.",
        )
        .aliases(&["whitebox_static"])
        .advanced(),
        opt("mode", OptionType::String, "Analysis mode.").advanced(),
        opt("preset", OptionType::String, "Analysis preset.").advanced(),
        model_option(),
    ]
}

pub(crate) fn variant_module() -> BuiltinModule {
    builtin_module(
        "variant",
        "Variant Hunter",
        ModuleKind::Offense,
        "Lift exploit patterns from confirmed findings and hunt sibling variants.",
        tools_with_policy(variant_policy(), variant_tools()),
        vec![dag("variant:hunt", "findings", &["variant:lift-pattern"])],
    )
}

fn variant_policy() -> ToolPolicy {
    workspace_policy(
        ToolPhase::Hunt,
        RuntimeRequirement::Always,
        FindingStoreRequirement::Required,
    )
}

fn variant_tools() -> Vec<ToolDescriptor> {
    vec![
        tool_with_options(
            "variant:hunt",
            "Hunt variants of a confirmed finding.",
            variant_hunt_options(),
        ),
        tool_with_options(
            "variant:lift-pattern",
            "Lift a reusable vulnerability pattern from a confirmed finding.",
            vec![fingerprint_option(), model_option()],
        ),
    ]
}

fn variant_hunt_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        fingerprint_option(),
        max_findings_option(25),
        opt(
            "includeVendored",
            OptionType::Bool,
            "Include vendored and third-party paths in the hunt scope.",
        )
        .aliases(&["include_vendored"])
        .default(json!(true))
        .advanced(),
        opt(
            "vendorPaths",
            OptionType::StringList,
            "Vendor path patterns for variant scope control.",
        )
        .aliases(&["vendor_paths"])
        .advanced(),
        model_option(),
    ]
}

pub(crate) fn ndiff_module() -> BuiltinModule {
    builtin_module(
        "ndiff",
        "N-Day Diff Hunter",
        ModuleKind::Intel,
        "Fetch CVE fix context, extract fix patterns, and hunt n-day variants.",
        ndiff_tools(),
        vec![dag(
            "ndiff:hunt-variants",
            "findings",
            &["ndiff:extract-fix-pattern"],
        )],
    )
}

fn ndiff_tools() -> Vec<ToolDescriptor> {
    vec![
        ndiff_fetch_tool().with_policy(external_action_policy(
            ToolPhase::Map,
            RuntimeRequirement::Never,
            FindingStoreRequirement::Optional,
        )),
        ndiff_extract_tool().with_policy(external_action_policy(
            ToolPhase::Map,
            RuntimeRequirement::Always,
            FindingStoreRequirement::Optional,
        )),
        ndiff_hunt_tool().with_policy(workspace_policy(
            ToolPhase::Map,
            RuntimeRequirement::Always,
            FindingStoreRequirement::Required,
        )),
    ]
}

fn ndiff_fetch_tool() -> ToolDescriptor {
    tool_with_options(
        "ndiff:fetch-cve",
        "Fetch CVE and patch metadata.",
        vec![
            opt("id", OptionType::String, "CVE or advisory id to fetch.").required(),
            opt(
                "offline",
                OptionType::Bool,
                "Use only supplied advisory fixtures.",
            )
            .default(json!(false))
            .advanced(),
            opt("record", OptionType::Json, "Inline advisory record JSON.").advanced(),
            opt(
                "fixtures",
                OptionType::Json,
                "Offline advisory fixture JSON.",
            )
            .advanced(),
            binary_option("curl binary path."),
        ],
    )
}

fn ndiff_extract_tool() -> ToolDescriptor {
    tool_with_options(
        "ndiff:extract-fix-pattern",
        "Extract a vulnerability fix pattern from a patch.",
        vec![
            target_option(),
            opt("record", OptionType::Json, "Advisory record JSON.").advanced(),
            opt("patchText", OptionType::String, "Patch text to analyze.")
                .aliases(&["patch_text"])
                .advanced(),
            opt("patchPath", OptionType::Path, "Patch file to analyze.")
                .aliases(&["patch_path"])
                .workspace_read()
                .advanced(),
            opt("patchUrl", OptionType::String, "Patch URL to fetch.")
                .aliases(&["patch_url"])
                .advanced(),
            opt(
                "thinkingLevel",
                OptionType::String,
                "Runtime thinking-level hint.",
            )
            .aliases(&["thinking_level"])
            .advanced(),
            model_option(),
        ],
    )
}

fn ndiff_hunt_tool() -> ToolDescriptor {
    tool_with_options(
        "ndiff:hunt-variants",
        "Hunt variants using an extracted n-day fix pattern.",
        vec![
            target_option(),
            max_findings_option(25),
            opt("advisoryId", OptionType::String, "CVE or advisory id.")
                .aliases(&["advisory_id", "cve"])
                .advanced(),
            opt("pattern", OptionType::Json, "Extracted fix pattern JSON.").advanced(),
            opt("record", OptionType::Json, "Advisory record JSON.").advanced(),
            opt(
                "fixtures",
                OptionType::Json,
                "Offline advisory fixture JSON.",
            )
            .advanced(),
            model_option(),
        ],
    )
}

pub(crate) fn randori_module() -> BuiltinModule {
    builtin_module(
        "randori",
        "Randori",
        ModuleKind::Intel,
        "Threat-model generation using PASTA stage framing and adversarial scenario review.",
        vec![
            randori_pasta_tool().with_policy(workspace_policy(
                ToolPhase::Map,
                RuntimeRequirement::Always,
                FindingStoreRequirement::Optional,
            )),
            randori_threat_model_tool()
                .with_policy(read_policy(ToolPhase::Map, WorkspaceRequirement::Required)),
        ],
        vec![dag(
            "randori:threat-model",
            "threat-model",
            &["context:build"],
        )],
    )
}

fn randori_pasta_tool() -> ToolDescriptor {
    tool_with_options(
        "randori:pasta",
        "Generate a PASTA threat model.",
        randori_pasta_options(),
    )
}

fn randori_threat_model_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "randori:threat-model",
        "Compatibility alias for threat-model PASTA artifacts.",
        randori_threat_model_options(),
    )
}

fn randori_pasta_options() -> Vec<OptionSpec> {
    let mut options = vec![
        target_option(),
        randori_output_dir_option(false, true),
        randori_slice_option(),
        opt(
            "stages",
            OptionType::StringList,
            "PASTA stages to generate.",
        )
        .advanced(),
    ];
    options.extend(randori_limit_options());
    options.push(model_option());
    options
}

fn randori_threat_model_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        randori_output_dir_option(true, false),
        opt(
            "methodology",
            OptionType::Enum,
            "Threat-model methodology overlay.",
        )
        .aliases(&["type"])
        .choices(&["pasta", "stride", "dread"])
        .default(json!("pasta")),
        model_option(),
    ]
}

fn randori_output_dir_option(required: bool, writes_state: bool) -> OptionSpec {
    let option = opt(
        "outputDir",
        OptionType::Path,
        "Directory for randori artifacts.",
    )
    .aliases(&["output_dir"]);
    let option = if writes_state {
        option.state_write()
    } else {
        option.workspace_read()
    };
    if required {
        option.required()
    } else {
        option.advanced()
    }
}

fn randori_slice_option() -> OptionSpec {
    opt("slice", OptionType::Enum, "Threat-model slice to generate.")
        .choices(&["all", "dfd", "stride", "stories", "scope", "scenarios"])
        .default(json!("all"))
        .advanced()
}

fn randori_limit_options() -> Vec<OptionSpec> {
    vec![
        opt("maxElements", OptionType::Int, "Maximum model elements.")
            .aliases(&["max_elements"])
            .default(json!(40))
            .advanced(),
        opt("maxThreats", OptionType::Int, "Maximum threats.")
            .aliases(&["max_threats"])
            .default(json!(30))
            .advanced(),
        opt(
            "emitFindings",
            OptionType::Bool,
            "Persist threats as findings.",
        )
        .aliases(&["emit_findings"])
        .default(json!(false))
        .advanced(),
        opt(
            "preserveUserEdits",
            OptionType::Bool,
            "Preserve existing user-edited threat model.",
        )
        .aliases(&["preserve_user_edits"])
        .default(json!(true))
        .advanced(),
    ]
}
