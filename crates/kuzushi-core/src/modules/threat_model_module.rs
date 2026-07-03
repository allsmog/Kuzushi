use super::*;

pub(crate) fn threat_model_module() -> BuiltinModule {
    builtin_module(
        "threat-model",
        "Threat Model",
        ModuleKind::Intel,
        "Build and read threat-model artifacts and methodology overlays.",
        vec![
            tool_with_options(
                "threat-model:build",
                "Build a threat model for the current target.",
                vec![
                    target_option(),
                    opt(
                        "methodology",
                        OptionType::Enum,
                        "Threat-model method: STRIDE gap-fill, PASTA stage framing, or DREAD scoring.",
                    )
                    .choices(&["pasta", "stride", "dread"])
                    .default(json!("stride")),
                    opt(
                        "sources",
                        OptionType::StringList,
                        "Parent artifacts to feed into the model: context, threat-model, x-ray, entry-points, or none.",
                    )
                    .aliases(&["sourceArtifacts", "source_artifacts"])
                    .default(json!(["context", "threat-model"])),
                    opt(
                        "seed",
                        OptionType::StringList,
                        "Operator seed context; each item may be inline text or a path.",
                    ),
                    opt(
                        "designDoc",
                        OptionType::Path,
                        "Architecture or design document to include as source context.",
                    )
                    .aliases(&["design_doc", "design"]),
                    opt(
                        "outputDir",
                        OptionType::Path,
                        "Directory for normalized threat-model artifacts.",
                    )
                    .aliases(&["output_dir"])
                    .advanced(),
                    opt("slice", OptionType::Enum, "Threat-model slice to generate.")
                        .choices(&["all", "dfd", "stride", "stories", "scope", "scenarios"])
                        .default(json!("all"))
                        .advanced(),
                    opt(
                        "stages",
                        OptionType::StringList,
                        "PASTA stages to generate.",
                    )
                    .advanced(),
                    opt(
                        "contextMode",
                        OptionType::Enum,
                        "How to handle the context snapshot source.",
                    )
                    .aliases(&["context_mode"])
                    .choices(&["auto", "refresh", "require", "off"])
                    .default(json!("auto"))
                    .advanced(),
                    opt(
                        "contextLimit",
                        OptionType::Int,
                        "Context snapshot file sample limit when building context.",
                    )
                    .aliases(&["contextSampleLimit", "context_sample_limit", "sampleLimit"])
                    .default(json!(200))
                    .advanced(),
                    opt(
                        "maxSourceBytes",
                        OptionType::Int,
                        "Maximum bytes from each source block included in the prompt.",
                    )
                    .aliases(&["max_source_bytes"])
                    .default(json!(200000))
                    .advanced(),
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
                    opt(
                        "THREAT_MODEL_PROMPT",
                        OptionType::String,
                        "Additional threat-model prompt guidance or a prompt file path.",
                    )
                    .advanced(),
                    model_option(),
                ],
            ),
            tool_with_options(
                "threat-model:read",
                "Read the current threat model artifact.",
                vec![
                    target_option(),
                    opt(
                        "outputDir",
                        OptionType::Path,
                        "Directory containing threat-model artifacts.",
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
                ],
            ),
            tool(
                "threat-model:methodologies",
                "List supported threat-model methodologies.",
            ),
        ],
        vec![dag(
            "threat-model:build",
            "threat-model",
            &["context:build"],
        )],
    )
}

pub(crate) fn x_ray_module() -> BuiltinModule {
    builtin_module(
        "x-ray",
        "X-Ray",
        ModuleKind::Intel,
        "Pashov X-Ray repository analysis and report artifacts.",
        vec![
            tool_with_options(
                "x-ray:run",
                "Run repository X-Ray analysis.",
                vec![
                    target_option(),
                    model_option(),
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
                ],
            ),
            tool("x-ray:read", "Read the latest X-Ray analysis report."),
        ],
        vec![dag("x-ray:x-ray", "report", &["context:build"])],
    )
}

pub(crate) fn dep_hygiene_module() -> BuiltinModule {
    builtin_module(
        "dep-hygiene",
        "Dependency Hygiene",
        ModuleKind::Defense,
        "Check dependency manifests for stale, vulnerable, or policy-risky packages.",
        vec![tool_with_options(
            "dep-hygiene:check",
            "Run dependency hygiene checks.",
            vec![target_option()],
        )],
        vec![dag("dep-hygiene:check", "findings", &["context:build"])],
    )
}

pub(crate) fn secret_scan_module() -> BuiltinModule {
    builtin_module(
        "secret-scan",
        "Secret Scan",
        ModuleKind::Defense,
        "Fast deterministic secret scanner over source files.",
        vec![tool_with_options(
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
                .default(json!(524288)),
                max_findings_option(1000),
            ],
        )],
        vec![dag("secret-scan:scan", "findings", &["context:build"])],
    )
}
