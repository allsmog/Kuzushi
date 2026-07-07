use super::*;

pub(crate) fn patch_module() -> BuiltinModule {
    builtin_module(
        "patch",
        "Patch",
        ModuleKind::Defense,
        "Generate and validate a patch for a finding.",
        vec![tool_with_options(
            "patch:finding",
            "Generate a patch for a finding.",
            vec![
                fingerprint_option(),
                opt("maxIterations", OptionType::Int, "Maximum patch attempts.")
                    .aliases(&["max_iterations"])
                    .default(json!(3)),
                opt("style", OptionType::Enum, "Patch generation style.")
                    .choices(&["minimal", "defensive"])
                    .default(json!("minimal")),
                opt(
                    "buildCmd",
                    OptionType::String,
                    "Build command used for patch validation.",
                )
                .aliases(&["build_cmd"])
                .advanced(),
                opt(
                    "testCmd",
                    OptionType::String,
                    "Test command used for patch validation.",
                )
                .aliases(&["test_cmd"])
                .advanced(),
                model_option(),
            ],
        )],
        vec![dag("patch:finding", "patch", &["verify:finding"])],
    )
}
