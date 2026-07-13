use super::*;

pub(crate) fn patch_module() -> BuiltinModule {
    builtin_module(
        "patch",
        "Patch",
        ModuleKind::Defense,
        "Generate and validate a patch for a finding.",
        vec![patch_finding_tool()],
        vec![dag("patch:finding", "patch", &["verify:finding"])],
    )
}

fn patch_finding_tool() -> ToolDescriptor {
    tool_with_options(
        "patch:finding",
        "Generate a patch for a finding.",
        patch_finding_options(),
    )
    .with_prompt(editable_prompt(
        "patch instructions",
        "patch",
        "finding",
        "PATCH_PROMPT",
        crate::remediation::patch::patch_system_prompt(),
    ))
    .with_policy(repository_execute_policy(
        ToolPhase::Fix,
        RuntimeRequirement::Always,
        FindingStoreRequirement::Required,
    ))
}

fn patch_finding_options() -> Vec<OptionSpec> {
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
        opt(
            "validationTimeoutMs",
            OptionType::Int,
            "Per-command deadline for git, build, and test patch validation in milliseconds. A deadline kills and reaps the complete process tree.",
        )
        .aliases(&["validation_timeout_ms"])
        .default(json!(
            crate::remediation::patch::DEFAULT_PATCH_VALIDATION_TIMEOUT_MS
        ))
        .advanced(),
        source_commit_binding_option(),
        model_option(),
        patch_prompt_option(),
    ]
}

fn source_commit_binding_option() -> OptionSpec {
    opt(
        crate::remediation::patch::PATCH_SOURCE_COMMIT_INPUT_KEY,
        OptionType::String,
        "Internal clean-source commit binding populated and verified by the registry.",
    )
    .advanced()
}

fn patch_prompt_option() -> OptionSpec {
    opt(
        "PATCH_PROMPT",
        OptionType::String,
        "System prompt text or workspace-file override for patch generation.",
    )
    .inline_or_workspace_file()
    .advanced()
}
