use super::*;

pub(crate) fn verify_module() -> BuiltinModule {
    builtin_module(
        "verify",
        "Verify",
        ModuleKind::Offense,
        "Exploitability verification through proof-of-concept construction and sandboxed execution.",
        vec![
            tool_with_options(
                "verify:finding",
                "Verify whether a finding is exploitable (LLM-driven; consults runtime for PoC reasoning).",
                verify_finding_options(),
            )
            .with_prompt(editable_prompt(
                "verification instructions",
                "verify",
                "finding",
                "VERIFY_PROMPT",
                crate::verification::DEFAULT_VERIFY_PROMPT.to_string(),
            ))
            .with_policy(workspace_policy(
                ToolPhase::Confirm,
                RuntimeRequirement::Always,
                FindingStoreRequirement::Required,
            )),
            hidden_tool_with_options(
                "verify:exploit",
                "Compatibility alias for verify:finding with mode=empirical.",
                vec![fingerprint_option()],
            )
            .with_policy(workspace_policy(
                ToolPhase::Confirm,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            )),
        ],
        vec![dag("verify:finding", "verification", &["triage:run"])],
    )
}

fn verify_finding_options() -> Vec<OptionSpec> {
    vec![
        fingerprint_option(),
        verification_mode_option(),
        verify_prompt_option(),
        verification_passes_option(),
        model_option(),
        mcps_option(),
        mcp_tool_timeout_ms_option(),
    ]
}

fn verification_mode_option() -> OptionSpec {
    opt("mode", OptionType::Enum, "Verification mode.")
        .choices(&["model", "empirical"])
        .default(json!("model"))
        .advanced()
}

fn verify_prompt_option() -> OptionSpec {
    opt(
        "VERIFY_PROMPT",
        OptionType::String,
        "Prompt text or path override for verification.",
    )
    .inline_or_workspace_file()
    .advanced()
}

fn verification_passes_option() -> OptionSpec {
    opt(
        "VERIFY_PASSES",
        OptionType::Int,
        "Independent adversarial verifier passes to run and combine by majority vote (1-7). Higher trades model spend for precision.",
    )
    .aliases(&["passes"])
    .default(json!(1))
    .advanced()
}
