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
    let local_policy = tool_policy(
        ToolPhase::Scan,
        RuntimeRequirement::Never,
        ToolEffect::WorkspaceWrite,
        WorkspaceRequirement::Optional,
        FindingStoreRequirement::Optional,
    );
    vec![
        pipeline_task_selector_tool().with_policy(local_policy),
        pipeline_approval_tool().with_policy(local_policy),
        pipeline_taint_cwe_select_tool().with_policy(workspace_policy(
            ToolPhase::Scan,
            RuntimeRequirement::InputAware,
            FindingStoreRequirement::Optional,
        )),
    ]
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
    .without_phase_result()
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
        "Propose source-analysis CWE classes using an approved allowance, or retain supplied classes without model work. Selection creates no Scan jobs or findings.",
        pipeline_taint_cwe_select_options(),
    ).with_allowance_category(AllowanceCategory::Scope).without_phase_result()
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
        "Draft source patterns from confirmed findings and search for related observations.",
        tools_with_policy(variant_policy(), variant_tools()),
        vec![dag("variant:hunt", "findings", &["variant:lift-pattern"])],
    )
}

fn variant_policy() -> ToolPolicy {
    workspace_policy(
        ToolPhase::Scan,
        RuntimeRequirement::Always,
        FindingStoreRequirement::Required,
    )
}

fn variant_tools() -> Vec<ToolDescriptor> {
    vec![
        tool_with_options(
            "variant:hunt",
            "Experimental source-only search for observations related to a currently confirmed finding. Search guidance does not establish enforced discovery scope or complete coverage. Results remain unverified and do not complete Scan. Approve this separate search and its allowance explicitly.",
            variant_hunt_options(),
        ).with_discovery_maturity(ModuleMaturity::Labs)
            .without_phase_result(),
        tool_with_options(
            "variant:lift-pattern",
            "Experimental source-pattern draft from a currently confirmed finding. Output remains unaccepted and does not change active context or start discovery. Use findings:lesson-generate for reviewed future context. Useful pattern quality and source-version isolation remain unqualified.",
            vec![fingerprint_option(),
                inherited_variant_reasoning_option(),
                model_option()],
        ).with_discovery_maturity(ModuleMaturity::Labs)
            .with_allowance_category(AllowanceCategory::Learning)
            .without_phase_result(),
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
        inherited_variant_reasoning_option(),
        model_option(),
    ]
}

pub(in crate::modules) fn inherited_variant_reasoning_option() -> OptionSpec {
    opt(
        "thinkingLevel",
        OptionType::Enum,
        "Reasoning effort; omit to inherit the selected runtime.",
    )
    .choices(&["low", "medium", "high", "xhigh"])
    .aliases(&["thinking_level"])
    .advanced()
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
    .labs()
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
            ToolPhase::Scan,
            RuntimeRequirement::Always,
            FindingStoreRequirement::Required,
        )),
    ]
}

fn ndiff_fetch_tool() -> ToolDescriptor {
    tool_with_options(
        "ndiff:fetch-cve",
        "Experimental advisory metadata retrieval. Supplied records are unverified. Live retrieval, cancellation and source applicability remain unqualified. Does not complete Map.",
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
            opt("maxMetadataBytes", OptionType::Int, "Combined encoded byte limit for supplied record and fixtures, from 1 to 8388608 bytes.")
                .integer_range(1, 8 * 1024 * 1024).default(json!(8 * 1024 * 1024)).advanced(),
            opt(
                "fixtures",
                OptionType::Json,
                "Offline advisory fixture JSON.",
            )
            .advanced(),
            binary_option("curl binary path."),
        ],
    )
    .with_discovery_maturity(ModuleMaturity::Labs)
    .without_phase_result()
}

fn ndiff_extract_tool() -> ToolDescriptor {
    tool_with_options(
        "ndiff:extract-fix-pattern",
        "Experimental advisory-pattern draft from a supplied existing diff. Output remains unaccepted and does not change context, start discovery or generate a patch. Learning allowance and explicit external-action authorization are required. Live retrieval and useful pattern quality remain unqualified.",
        ndiff_extract_options(),
    )
    .with_discovery_maturity(ModuleMaturity::Labs)
    .with_allowance_category(AllowanceCategory::Learning)
    .without_phase_result()
}

fn ndiff_extract_options() -> Vec<OptionSpec> {
    let mut options = vec![
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
        inherited_variant_reasoning_option(),
        model_option(),
    ];
    options.extend(ndiff_extract_source_options());
    options.extend(ndiff_extract_limits());
    options
}

pub(in crate::modules) fn ndiff_extract_source_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "id",
            OptionType::String,
            "Optional advisory id when diff content is absent.",
        )
        .aliases(&["advisoryId", "advisory_id", "cve"])
        .advanced(),
        opt(
            "offline",
            OptionType::Bool,
            "Use supplied diff text or files and advisory fixtures without live retrieval.",
        )
        .default(json!(false))
        .advanced(),
        opt(
            "fixtures",
            OptionType::Json,
            "Supplied advisory fixture JSON.",
        )
        .advanced(),
        opt(
            "patchFixtures",
            OptionType::Json,
            "Supplied URL-to-diff-text fixture JSON.",
        )
        .aliases(&["patch_fixtures"])
        .advanced(),
        binary_option("curl executable for explicit live retrieval."),
    ]
}

pub(in crate::modules) fn ndiff_extract_limits() -> Vec<OptionSpec> {
    vec![
        opt("maxMetadataBytes", OptionType::Int, "Combined encoded limit for supplied advisory and diff fixtures.").integer_range(1, 8 * 1024 * 1024).default(json!(65536)).advanced(),
        opt("maxPatchBytes", OptionType::Int, "Accepted existing diff bytes after resolution. Live transport limits are separate.").integer_range(1, 8 * 1024 * 1024).default(json!(256 * 1024)).advanced(),
        opt("maxSourceBytes", OptionType::Int, "Maximum diff excerpt bytes supplied to the model; omitted material is disclosed.").integer_range(256, 128 * 1024).default(json!(18000)).advanced(),
        opt("maxContextBytes", OptionType::Int, "Maximum complete metadata and excerpt prompt bytes before a request.").integer_range(1024, 512 * 1024).default(json!(65536)).advanced(),
        opt("maxOutputTokens", OptionType::Int, "Requested response tokens per initial or repair query. Adapter support varies; use approved call limits for spending control.").aliases(&["max_output_tokens", "maxTokens"]).integer_range(256, 32768).default(json!(4096)).advanced(),
        opt("maxModelTurns", OptionType::Int, "Maximum model turns per initial or repair query; this draft has no source tools.").aliases(&["max_model_turns"]).integer_range(1, 4).default(json!(1)).advanced(),
    ]
}

fn ndiff_hunt_tool() -> ToolDescriptor {
    tool_with_options(
        "ndiff:hunt-variants",
        "Experimental source observations guided by an explicitly supplied advisory pattern. Results require independent review and do not establish complete coverage, enforced discovery scope or advisory applicability. Approve this separate search and its allowance.",
        ndiff_hunt_options(),
    )
    .with_discovery_maturity(ModuleMaturity::Labs)
    .without_phase_result()
}

fn ndiff_hunt_options() -> Vec<OptionSpec> {
    let mut options = vec![
            target_option(),
            max_findings_option(25).integer_range(1, 100),
            opt("advisoryId", OptionType::String, "CVE or advisory id.")
                .aliases(&["advisory_id", "cve"])
                .advanced(),
            opt("pattern", OptionType::Json, "Supplied advisory pattern JSON. Nonblank fixShape and vulnerableShape are required; this input does not accept a reusable lesson.").required().advanced(),
            opt("record", OptionType::Json, "Advisory record JSON.").advanced(),
            opt(
                "fixtures",
                OptionType::Json,
                "Offline advisory fixture JSON.",
            )
            .advanced(),
            model_option(),
        ];
    options.extend(ndiff_query_options());
    options
}

fn ndiff_query_options() -> Vec<OptionSpec> {
    vec![
        inherited_variant_reasoning_option(),
        opt("includeVendored", OptionType::Bool, "Search guidance for vendored paths. This does not enforce an exact file scope.")
            .aliases(&["include_vendored"]).default(json!(true)).advanced(),
        opt("maxOutputTokens", OptionType::Int, "Requested response tokens per initial or repair query. Adapter support varies; use approved call limits for spending control.")
            .aliases(&["max_output_tokens", "maxTokens"]).integer_range(256, 32768).default(json!(4096)).advanced(),
        opt("maxModelTurns", OptionType::Int, "Maximum model turns per initial or repair query.")
            .aliases(&["max_model_turns"]).integer_range(1, 16).default(json!(4)).advanced(),
    ]
}

pub(crate) fn randori_module() -> BuiltinModule {
    builtin_module(
        "randori",
        "Randori",
        ModuleKind::Intel,
        "Threat-model generation using PASTA stage framing and adversarial scenario review.",
        vec![
            randori_pasta_tool()
                .with_policy(workspace_policy(
                    ToolPhase::Map,
                    RuntimeRequirement::Always,
                    FindingStoreRequirement::Optional,
                ))
                .without_phase_result()
                .with_allowance_category(AllowanceCategory::Context)
                .with_discovery_maturity(ModuleMaturity::Labs),
            randori_threat_model_tool()
                .with_policy(read_policy(ToolPhase::Map, WorkspaceRequirement::Required))
                .without_phase_result()
                .with_discovery_maturity(ModuleMaturity::Compatibility),
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
        "Experimental PASTA draft artifacts. Active context stays unchanged; import and accept the draft before scanning.",
        randori_pasta_options(),
    )
}

fn randori_threat_model_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "randori:threat-model",
        "Read historical PASTA artifacts without accepting context. Prefer threat-model:read with the same outputDir and methodology=pasta.",
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
            "PASTA stage labels supplied to one synthesis request.",
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
        randori_legacy_model_option(),
    ]
}

fn randori_legacy_model_option() -> OptionSpec {
    let mut option = model_option().advanced();
    option.description =
        "Legacy input accepted but ignored. Reading artifacts makes no model request.".into();
    option
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
            .integer_range(5, 500)
            .default(json!(40))
            .advanced(),
        opt("maxThreats", OptionType::Int, "Maximum threats.")
            .aliases(&["max_threats"])
            .integer_range(1, 500)
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
            "Preserve existing draft files. Reusing outputDir requires an explicit false value; active context is never replaced.",
        )
        .aliases(&["preserve_user_edits"])
        .default(json!(true))
        .advanced(),
    ]
}
