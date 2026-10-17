use super::*;

pub(crate) fn full_mode_module() -> BuiltinModule {
    builtin_module(
        "full-mode",
        "Chunked source analysis",
        ModuleKind::Offense,
        "Compatibility entry for chunked source analysis. Use standard agentic SAST for accepted scope and context.",
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
            ).without_phase_result()],
        ),
        vec![],
    ).compatibility()
}

fn full_mode_hunt_options() -> Vec<OptionSpec> {
    let mut options = full_mode_planning_options();
    options.extend([
        opt(
            "budgetUsd",
            OptionType::Float,
            "Stop starting chunks after observed cost reaches this amount. A request can exceed it and charges may be unknown. Approved call limits remain required.",
        ),
        full_mode_scope_file_option(),
        full_mode_failed_chunk_ids_option(),
        chunked_cache_option().default(json!(true)),
        full_mode_auto_triage_option(),
        full_mode_auto_triage_max_steps_option(),
        full_mode_auto_triage_deposit_option(),
    ]);
    options
}

fn full_mode_planning_options() -> Vec<OptionSpec> {
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
            "Approximate input tokens per chunk for file grouping.",
        )
        .default(serde_json::json!(12_000))
        .integer_range(1, i64::MAX),
        opt(
            "depositUsdPerChunk",
            OptionType::Float,
            "Initial spend ticket per chunk; refunded with the bridge's reported cost.",
        )
        .default(serde_json::json!(2.0)),
        opt(
            "dryRun",
            OptionType::Bool,
            "Plan without model calls using bounded inventory and source limits (100000 entries/files, 512 MiB source). Partial plans require a smaller explicit scope before execution.",
        )
        .default(serde_json::json!(false)),
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

pub(super) fn full_mode_failed_chunk_ids_option() -> OptionSpec {
    opt(
        "failedChunkIds",
        OptionType::Json,
        "Retry selection supplied in run input: a comma-separated string or an array of chunk IDs. Empty or unknown IDs are refused. Replan after source changes.",
    )
}

pub(super) fn chunked_cache_option() -> OptionSpec {
    opt(
        "reuseCachedChunks",
        OptionType::Bool,
        "Reuse identical chunk results. Set false for independent discovery; fresh requests consume the approved allowance. The compatibility default is true.",
    ).advanced()
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
        "Experimental finding-metadata prioritization with a historical percentile threshold. No source review or follow-up execution.",
        vec![classifier_score_tool().with_policy(workspace_policy(
                ToolPhase::Review,
                RuntimeRequirement::Always,
                FindingStoreRequirement::Optional,
            ))
            .without_phase_result()
            .with_allowance_category(AllowanceCategory::Review)
            .with_discovery_maturity(ModuleMaturity::Labs)],
        vec![],
    )
}

fn classifier_score_tool() -> ToolDescriptor {
    tool_with_options(
                "classifier-gate:score",
                "Experimental prioritization opinion over finding metadata. Requires Review allowance; cannot complete Review or start follow-up work.",
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
            )
}

pub(crate) fn deep_audit_module() -> BuiltinModule {
    builtin_module(
        "deep-audit",
        "Deep auditor",
        ModuleKind::Triage,
        "Legacy independent deep auditor. Use the guided Review plan for source-bound review.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Review,
                RuntimeRequirement::Always,
                FindingStoreRequirement::Optional,
            ),
            vec![deep_audit_tool()],
        ),
        vec![],
    )
    .compatibility()
}

fn deep_audit_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "deep-audit:run",
        "Legacy independent deep-audit action. Use campaign:review-study and triage:run for approved source-bound Review.",
        deep_audit_options(),
    )
}

fn deep_audit_options() -> Vec<OptionSpec> {
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
        opt(
            "passes",
            OptionType::Int,
            "Independent consensus audit passes; majority verdict is reported when > 1.",
        )
        .default(serde_json::json!(1)),
        opt(
            "temperature",
            OptionType::Float,
            "Sampling temperature for every audit round-trip.",
        )
        .default(serde_json::json!(0.0)),
        crate::modules::triage_module::taint_tools_option(),
    ]
}
