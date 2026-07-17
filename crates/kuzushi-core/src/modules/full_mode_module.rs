use super::*;

pub(crate) fn full_mode_module() -> BuiltinModule {
    builtin_module(
        "full-mode",
        "Full-codebase scan",
        ModuleKind::Offense,
        "Whole-codebase chunked LLM pass — token-greedy file clustering, per-chunk model query.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Scan,
                RuntimeRequirement::InputAware,
                FindingStoreRequirement::Optional,
            ),
            vec![hidden_tool_with_options(
                "full-mode:hunt",
                "Compatibility alias for agentic-sast:scan with strategy=chunked.",
                full_mode_hunt_options(),
            )],
        ),
        vec![],
    )
}

fn full_mode_hunt_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "language",
            OptionType::Enum,
            "Per-chunk system prompt selector.",
        )
        .choices(&["c", "unknown"])
        .default(serde_json::json!("c")),
        opt(
            "maxTokensPerChunk",
            OptionType::Int,
            "Token budget per chunk; chunks pack files up to this cap.",
        )
        .default(serde_json::json!(12_000)),
        opt(
            "depositUsdPerChunk",
            OptionType::Float,
            "Initial spend ticket per chunk; refunded with the bridge's reported cost.",
        )
        .default(serde_json::json!(2.0)),
        opt(
            "dryRun",
            OptionType::Bool,
            "Plan + cost estimate only; do not invoke any model.",
        )
        .default(serde_json::json!(false)),
        full_mode_scope_file_option(),
        full_mode_failed_chunk_ids_option(),
        full_mode_auto_triage_option(),
        full_mode_auto_triage_max_steps_option(),
        full_mode_auto_triage_deposit_option(),
    ]
}

fn full_mode_scope_file_option() -> OptionSpec {
    opt(
        "scopeFile",
        OptionType::Path,
        "Optional repo-relative path to a newline-delimited scope file. Defaults to <target>/.kuzushi/v3/since.txt when --since populated it.",
    )
    .workspace_read()
}

fn full_mode_failed_chunk_ids_option() -> OptionSpec {
    opt(
        "failedChunkIds",
        OptionType::String,
        "Optional retry filter: comma-separated chunk IDs (\"3,7,11\") or JSON array when using run JSON input.",
    )
}

fn full_mode_auto_triage_option() -> OptionSpec {
    opt(
        "autoTriage",
        OptionType::Bool,
        "Run deep-audit on every HIGH+CRITICAL finding before returning. Verdicts are saved back into the findings store.",
    )
    .default(serde_json::json!(false))
}

fn full_mode_auto_triage_max_steps_option() -> OptionSpec {
    opt(
        "autoTriageMaxSteps",
        OptionType::Int,
        "Step budget per auto-triage deep-audit pass (default 12).",
    )
}

fn full_mode_auto_triage_deposit_option() -> OptionSpec {
    opt(
        "autoTriageDepositUsd",
        OptionType::Float,
        "Spend deposit per auto-triage pass (default 1.0; deep-audit refunds the unused portion).",
    )
}

pub(crate) fn classifier_gate_module() -> BuiltinModule {
    hidden_module(
        "classifier-gate",
        "Classifier gate",
        ModuleKind::Triage,
        "Cheap LLM classifier with adaptive p80 quantile gate. Score one finding to decide whether the deep auditor should run.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Review,
                RuntimeRequirement::Always,
                FindingStoreRequirement::Optional,
            ),
            vec![tool_with_options(
                "classifier-gate:score",
                "Score a finding with the cheap classifier; updates the running quantile.",
                vec![
                opt(
                    "findingFingerprint",
                    OptionType::String,
                    "Fingerprint (or short prefix) of the finding to score.",
                )
                .required(),
                opt(
                    "targetPercentile",
                    OptionType::Float,
                    "Target percentile for the adaptive threshold (0.0 < p < 1.0).",
                )
                .default(serde_json::json!(0.80)),
                ],
            )],
        ),
        vec![],
    )
}

pub(crate) fn deep_audit_module() -> BuiltinModule {
    builtin_module(
        "deep-audit",
        "Deep auditor",
        ModuleKind::Triage,
        "Tool-augmented LLM auditor — uses code-nav primitives to verify a finding's triggerability.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Review,
                RuntimeRequirement::Always,
                FindingStoreRequirement::Optional,
            ),
            vec![hidden_tool_with_options(
                "deep-audit:run",
                "Compatibility alias for triage:run with strategy=deep.",
                vec![
                opt(
                    "findingFingerprint",
                    OptionType::String,
                    "Fingerprint (or short prefix) of the finding to audit.",
                )
                .required(),
                opt(
                    "maxSteps",
                    OptionType::Int,
                    "Hard cap on tool-loop steps per finding.",
                )
                .default(serde_json::json!(24)),
                opt(
                    "depositUsd",
                    OptionType::Float,
                    "Initial spend ticket; refunded with the bridge's reported cost.",
                )
                .default(serde_json::json!(1.0)),
                ],
            )],
        ),
        vec![],
    )
}
