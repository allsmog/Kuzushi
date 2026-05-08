use super::prelude::*;
use super::*;

pub(crate) fn triage_module() -> BuiltinModule {
    builtin_module(
        "triage",
        "Triage",
        ModuleKind::Defense,
        "LLM-driven triage of scanner findings with evidence-backed verdicts.",
        vec![tool_with_options(
            "triage:run",
            "Triage findings with pi-agent-core.",
            vec![
                opt("scanId", OptionType::String, "Scan run id to triage."),
                opt(
                    "fingerprint",
                    OptionType::String,
                    "Single finding fingerprint to triage.",
                ),
                opt(
                    "batchSize",
                    OptionType::Int,
                    "Maximum findings per runtime batch.",
                )
                .default(json!(20)),
                model_option(),
            ],
        )],
        vec![dag("triage:run", "triage", &["semgrep:scan"])],
    )
}

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
                vec![fingerprint_option(), model_option()],
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
                opt("maxIterations", OptionType::Int, "Maximum patch attempts.").default(json!(3)),
                opt(
                    "buildCmd",
                    OptionType::String,
                    "Build command used for patch validation.",
                )
                .advanced(),
                opt(
                    "testCmd",
                    OptionType::String,
                    "Test command used for patch validation.",
                )
                .advanced(),
            ],
        )],
        vec![dag("patch:finding", "patch", &["verify:finding"])],
    )
}

pub(crate) fn findings_module() -> BuiltinModule {
    builtin_module(
        "findings",
        "Findings",
        ModuleKind::Defense,
        "Persist and inspect findings in SQLite.",
        vec![tool_with_options(
            "findings:list",
            "List persisted findings.",
            vec![
                opt("limit", OptionType::Int, "Maximum findings to return.").default(json!(50)),
                opt(
                    "name",
                    OptionType::String,
                    "Substring filter for finding titles.",
                ),
                opt("filePath", OptionType::Path, "File path filter."),
            ],
        )],
        vec![],
    )
}
