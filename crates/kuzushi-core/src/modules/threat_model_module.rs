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
                        "Threat-model methodology overlay.",
                    )
                    .choices(&["pasta", "stride", "dread"])
                    .default(json!("stride")),
                    model_option(),
                ],
            ),
            tool(
                "threat-model:read",
                "Read the current threat model artifact.",
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
                .default(json!(524288)),
                max_findings_option(1000),
            ],
        )],
        vec![dag("secret-scan:scan", "findings", &["context:build"])],
    )
}
