use super::*;

pub(crate) fn pipeline_module() -> BuiltinModule {
    hidden_module(
        "pipeline",
        "Pipeline",
        ModuleKind::Internal,
        "Internal orchestrator DAG nodes for task selection, approval gates, and taint sub-tasks.",
        vec![],
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

pub(crate) fn variant_module() -> BuiltinModule {
    builtin_module(
        "variant",
        "Variant Hunter",
        ModuleKind::Offense,
        "Lift exploit patterns from confirmed findings and hunt sibling variants.",
        vec![
            tool_with_options(
                "variant:lift-pattern",
                "Lift a reusable vulnerability pattern from a confirmed finding.",
                vec![fingerprint_option(), model_option()],
            ),
            tool_with_options(
                "variant:hunt",
                "Hunt variants of a confirmed finding.",
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
                ],
            ),
        ],
        vec![dag("variant:hunt", "findings", &["variant:lift-pattern"])],
    )
}

pub(crate) fn ndiff_module() -> BuiltinModule {
    builtin_module(
        "ndiff",
        "N-Day Diff Hunter",
        ModuleKind::Intel,
        "Fetch CVE fix context, extract fix patterns, and hunt n-day variants.",
        vec![
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
            ),
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
            ),
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
            ),
        ],
        vec![dag(
            "ndiff:hunt-variants",
            "findings",
            &["ndiff:extract-fix-pattern"],
        )],
    )
}

pub(crate) fn randori_module() -> BuiltinModule {
    builtin_module(
        "randori",
        "Randori",
        ModuleKind::Intel,
        "PASTA and randori threat-model generation.",
        vec![
            tool_with_options(
                "randori:pasta",
                "Generate a PASTA threat model.",
                vec![
                    target_option(),
                    opt(
                        "outputDir",
                        OptionType::Path,
                        "Directory for randori PASTA artifacts.",
                    )
                    .aliases(&["output_dir"])
                    .advanced(),
                    opt("slice", OptionType::Enum, "Threat-model slice to generate.")
                        .choices(&["all", "dfd", "stride", "stories", "scope", "scenarios"])
                        .default(json!("all"))
                        .advanced(),
                    opt("stages", OptionType::StringList, "PASTA stages to generate.")
                        .advanced(),
                    opt("maxElements", OptionType::Int, "Maximum model elements.")
                        .aliases(&["max_elements"])
                        .default(json!(40))
                        .advanced(),
                    opt("maxThreats", OptionType::Int, "Maximum threats.")
                        .aliases(&["max_threats"])
                        .default(json!(30))
                        .advanced(),
                    opt("emitFindings", OptionType::Bool, "Persist threats as findings.")
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
                    model_option(),
                ],
            ),
            tool_with_options(
                "randori:threat-model",
                "Generate a randori threat model.",
                vec![
                    target_option(),
                    opt(
                        "outputDir",
                        OptionType::Path,
                        "Directory containing randori artifacts.",
                    )
                    .aliases(&["output_dir"])
                    .required(),
                    opt(
                        "methodology",
                        OptionType::Enum,
                        "Threat-model methodology overlay.",
                    )
                    .aliases(&["type"])
                    .choices(&["pasta", "stride", "dread"])
                    .default(json!("pasta")),
                    model_option(),
                ],
            ),
        ],
        vec![dag(
            "randori:threat-model",
            "threat-model",
            &["context:build"],
        )],
    )
}
