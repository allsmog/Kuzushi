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
                vec![
                    fingerprint_option(),
                    opt(
                        "VERIFY_PROMPT",
                        OptionType::String,
                        "Prompt text or path override for verification.",
                    )
                    .advanced(),
                    opt(
                        "VERIFY_PASSES",
                        OptionType::Int,
                        "Independent adversarial verifier passes to run and combine by majority vote (1-7). Higher trades model spend for precision.",
                    )
                    .aliases(&["passes"])
                    .default(json!(1))
                    .advanced(),
                    model_option(),
                ],
            ),
            tool_with_options(
                "verify:exploit",
                "Empirical exploit-gated verify: scaffolds a sandboxed test harness from the finding's location and observes whether it crashes. Only Rust language is wired today; other languages return language_unsupported_yet.",
                vec![fingerprint_option()],
            ),
        ],
        vec![dag("verify:finding", "verification", &["triage:run"])],
    )
}
