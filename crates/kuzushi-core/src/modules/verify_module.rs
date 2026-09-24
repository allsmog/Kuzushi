use super::*;

pub(crate) fn verify_module() -> BuiltinModule {
    builtin_module(
        "verify",
        "Verify",
        ModuleKind::Offense,
        "Finding verification through source analysis or isolated local reproduction.",
        vec![
            tool_with_options(
                "verify:finding",
                "Assess a finding from source, or attempt isolated local reproduction in empirical mode.",
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
                ToolPhase::Prove,
                RuntimeRequirement::InputAware,
                FindingStoreRequirement::Required,
            )),
            hidden_tool_with_options(
                "verify:exploit",
                "Empirically verify a finding with an isolated proof harness.",
                vec![fingerprint_option()],
            )
            .with_policy(repository_execute_policy(
                ToolPhase::Prove,
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
        gate_model_option(),
        escalation_model_option(),
        mcps_option(),
        mcp_tool_timeout_ms_option(),
        max_model_turns_option(),
    ]
}

fn gate_model_option() -> OptionSpec {
    opt(
        "gateModel",
        OptionType::String,
        "Cheap-tier plausibility gate model (provider:modelId). Only its NOT-exploitable verdict is trusted; an exploitable gate verdict escalates to the full-strength panel on `model`. Unset means no gate.",
    )
    .aliases(&["gate_model"])
    .advanced()
}

fn escalation_model_option() -> OptionSpec {
    opt(
        "escalationModel",
        OptionType::String,
        "Different tie-break model (provider:modelId) consulted only when the panel splits evenly. Must differ from `model`; a same-model or invalid spec is refused and the split verdict stands. Unset means splits are not escalated.",
    )
    .aliases(&["escalation_model"])
    .advanced()
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
