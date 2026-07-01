use super::*;

pub(crate) fn triage_module() -> BuiltinModule {
    builtin_module(
        "triage",
        "Triage",
        ModuleKind::Defense,
        "LLM-driven triage of scanner findings with evidence-backed verdicts.",
        vec![triage_run_tool()],
        vec![dag("triage:run", "triage", &["semgrep:scan"])],
    )
}

fn triage_run_tool() -> ToolDescriptor {
    tool_with_options(
        "triage:run",
        "Triage findings with LangGraph.",
        triage_run_options(),
    )
}

fn triage_run_options() -> Vec<OptionSpec> {
    vec![
        opt("scanId", OptionType::String, "Scan run id to triage.").aliases(&["scan_id"]),
        triage_fingerprint_option(),
        triage_fingerprints_option(),
        triage_concurrency_option(),
        triage_cost_cap_option(),
        triage_prefilter_option(),
        triage_retriage_option(),
        triage_stage2_tier_option(),
        triage_prompt_option(),
        model_option(),
    ]
}

fn triage_fingerprint_option() -> OptionSpec {
    opt(
        "fingerprint",
        OptionType::String,
        "Single finding fingerprint to triage.",
    )
}

fn triage_fingerprints_option() -> OptionSpec {
    opt(
        "fingerprints",
        OptionType::StringList,
        "Finding fingerprints to triage.",
    )
    .advanced()
}

fn triage_concurrency_option() -> OptionSpec {
    opt(
        "concurrency",
        OptionType::Int,
        "Maximum concurrent triage requests.",
    )
    .default(json!(8))
    .advanced()
}

fn triage_cost_cap_option() -> OptionSpec {
    opt(
        "costCapUsd",
        OptionType::Float,
        "Maximum triage spend for this run.",
    )
    .aliases(&["cost_cap_usd"])
    .advanced()
}

fn triage_prefilter_option() -> OptionSpec {
    opt(
        "prefilterThreshold",
        OptionType::Int,
        "Stage-1 heuristic score threshold.",
    )
    .aliases(&["prefilter_threshold"])
    .default(json!(0))
    .advanced()
}

fn triage_retriage_option() -> OptionSpec {
    opt(
        "retriage",
        OptionType::Bool,
        "Re-run model triage for findings that already have persisted verdicts.",
    )
    .aliases(&["force", "includeTriaged", "include_triaged"])
    .default(json!(false))
    .advanced()
}

fn triage_stage2_tier_option() -> OptionSpec {
    opt(
        "stage2Tier",
        OptionType::Enum,
        "Stage-2 model routing tier.",
    )
    .aliases(&["stage2_tier"])
    .choices(&["cheap", "mid", "deep"])
    .default(json!("cheap"))
    .advanced()
}

fn triage_prompt_option() -> OptionSpec {
    opt(
        "TRIAGE_PROMPT",
        OptionType::String,
        "Prompt text or path override for triage.",
    )
    .advanced()
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
                opt("filePath", OptionType::Path, "File path filter.").aliases(&["file_path"]),
                opt(
                    "severity",
                    OptionType::StringList,
                    "Severity filter: critical, high, medium, low, info.",
                ),
                opt("verdict", OptionType::StringList, "Triage verdict filter."),
                opt(
                    "vulnSource",
                    OptionType::StringList,
                    "Discovery channel filter.",
                )
                .aliases(&["vuln_source"]),
            ],
        )],
        vec![],
    )
}
