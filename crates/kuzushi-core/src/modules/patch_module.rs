use super::*;

pub(crate) fn patch_module() -> BuiltinModule {
    builtin_module(
        "patch",
        "Patch",
        ModuleKind::Defense,
        "Generate and validate a patch for a finding.",
        vec![patch_finding_tool(), patch_reverify_tool()],
        vec![dag("patch:finding", "patch", &["verify:finding"])],
    )
}

fn patch_reverify_tool() -> ToolDescriptor {
    tool_with_options(
        "patch:reverify",
        "Re-run the originating detector against an applied patch.",
        vec![
            opt(
                "applicationId",
                OptionType::String,
                "Durable patch application receipt to re-verify.",
            )
            .aliases(&["application_id"])
            .required(),
            internal_reverify_option("detectorTool", "Bound originating detector name."),
            internal_reverify_option("detectorRunId", "Bound originating detector run."),
            opt(
                "detectorInput",
                OptionType::Json,
                "Bound originating detector input.",
            )
            .advanced(),
            internal_reverify_option(
                "comparisonUnavailable",
                "Reason the originating detector cannot be replayed exactly.",
            ),
        ],
    )
    .with_policy(repository_execute_policy(
        ToolPhase::Fix,
        RuntimeRequirement::InputAware,
        FindingStoreRequirement::Required,
    ))
}

fn internal_reverify_option(name: &str, description: &str) -> OptionSpec {
    opt(name, OptionType::String, description).advanced()
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
    .with_allowance_category(AllowanceCategory::Review)
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
        repository_source_commit_binding_option(),
        repository_target_scope_binding_option(),
        model_option(),
        patch_prompt_option(),
    ]
}

pub(in crate::modules) fn repository_source_commit_binding_option() -> OptionSpec {
    opt(
        crate::remediation::patch::PATCH_SOURCE_COMMIT_INPUT_KEY,
        OptionType::String,
        "Internal clean-source commit binding populated and verified by the registry.",
    )
    .advanced()
}

pub(in crate::modules) fn repository_target_scope_binding_option() -> OptionSpec {
    opt(
        crate::remediation::patch::REPOSITORY_TARGET_SCOPE_INPUT_KEY,
        OptionType::String,
        "Internal Git target-scope binding populated and verified by the registry.",
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
