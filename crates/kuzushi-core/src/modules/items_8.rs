use super::prelude::*;
use super::*;

pub(crate) fn full_mode_module() -> BuiltinModule {
    builtin_module(
        "full-mode",
        "Full-codebase scan",
        ModuleKind::Offense,
        "Whole-codebase chunked LLM pass — token-greedy file clustering, per-chunk model query.",
        vec![tool_with_options(
            "full-mode:hunt",
            "Run a chunked LLM scan over the target. Use dryRun=true to plan + estimate cost without spending tokens.",
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
                .default(serde_json::json!(120_000)),
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
                opt(
                    "scopeFile",
                    OptionType::Path,
                    "Optional repo-relative path to a newline-delimited scope file. Defaults to <target>/.kuzushi/v2/since.txt when --since populated it.",
                ),
            ],
        )],
        vec![],
    )
}

pub(crate) fn classifier_gate_module() -> BuiltinModule {
    builtin_module(
        "classifier-gate",
        "Classifier gate",
        ModuleKind::Triage,
        "Cheap LLM classifier with adaptive p80 quantile gate. Score one finding to decide whether the deep auditor should run.",
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
        vec![],
    )
}

pub(crate) fn deep_audit_module() -> BuiltinModule {
    builtin_module(
        "deep-audit",
        "Deep auditor",
        ModuleKind::Triage,
        "Tool-augmented LLM auditor — uses code-nav primitives to verify a finding's triggerability.",
        vec![tool_with_options(
            "deep-audit:run",
            "Run the deep auditor on a single finding; persists triage outcome + evidence.",
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
        vec![],
    )
}
