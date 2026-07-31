use super::*;

pub(crate) fn triage_module() -> BuiltinModule {
    builtin_module(
        "triage",
        "Triage",
        ModuleKind::Defense,
        "LLM-driven triage of scanner findings with evidence-backed verdicts.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Review,
                RuntimeRequirement::Always,
                FindingStoreRequirement::Required,
            ),
            vec![
                triage_run_tool(),
                triage_chain_hunt_tool(),
                triage_dedupe_tool(),
            ],
        ),
        vec![dag("triage:run", "triage", &["semgrep:scan"])],
    )
}

fn triage_run_tool() -> ToolDescriptor {
    tool_with_options(
        "triage:run",
        "Review scanner findings with evidence-backed model verdicts and persist triage state.",
        triage_run_options(),
    )
    .with_prompt(editable_prompt(
        "triage instructions",
        "triage",
        "run",
        "TRIAGE_PROMPT",
        crate::runtime::DEFAULT_TRIAGE_PROMPT.to_string(),
    ))
}

fn triage_chain_hunt_tool() -> ToolDescriptor {
    tool_with_options(
        "triage:chain-hunt",
        "Compose confirmed findings into attack chains (two or more findings where one \
         enables or escalates another) with an ordered attack path, cumulative impact, and \
         detection-difficulty narrative; each member-resolved chain persists as an open finding \
         (tool `chains`, rule `chains/model`) for the next triage pass.",
        chain_hunt_options(),
    )
}

fn triage_dedupe_tool() -> ToolDescriptor {
    tool_with_options(
        "triage:dedupe",
        "Model-driven corpus dedupe across all runs and tools: a judge proposes duplicate \
         groups over the fingerprint-keyed ledger, low-confidence groups escalate to one \
         code-reading confirmation pass, and confirmed duplicates rekey onto their canonical \
         finding with a false_positive/duplicate verdict.",
        dedupe_options(),
    )
}

fn dedupe_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "maxGroups",
            OptionType::Int,
            "Maximum accepted duplicate groups per run.",
        )
        .aliases(&["max_groups"])
        .default(json!(16)),
        opt(
            "maxCandidates",
            OptionType::Int,
            "Cap on ledger candidates shown to the dedupe judge.",
        )
        .aliases(&["max_candidates"])
        .default(json!(200))
        .advanced(),
        opt(
            "maxEscalations",
            OptionType::Int,
            "Cap on low-confidence groups escalated to a code-reading confirmation pass.",
        )
        .aliases(&["max_escalations"])
        .default(json!(4))
        .advanced(),
        opt(
            "dryRun",
            OptionType::Bool,
            "Report proposed duplicate groups without writing rekeys or verdicts.",
        )
        .aliases(&["dry_run"])
        .default(json!(false)),
        model_option(),
    ]
}

fn chain_hunt_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "maxChains",
            OptionType::Int,
            "Maximum member-resolved chains to persist per hunt.",
        )
        .aliases(&["max_chains"])
        .default(json!(8)),
        model_option(),
    ]
}

fn triage_run_options() -> Vec<OptionSpec> {
    let mut options = vec![
        opt("scanId", OptionType::String, "Scan run id to triage.").aliases(&["scan_id"]),
        triage_scope_option(),
        triage_fingerprint_option(),
        triage_fingerprints_option(),
        triage_concurrency_option(),
        triage_cost_cap_option(),
        triage_prefilter_option(),
        triage_retriage_option(),
        triage_dedupe_flag_option(),
        triage_votes_option(),
        triage_stage2_tier_option(),
        triage_strategy_option(),
        deep_triage_options(),
        taint_tools_option(),
        triage_prompt_option(),
        model_option(),
    ];
    options.extend(deep_triage_advanced_options());
    options
}

/// Dataflow tools offered to the deep auditor. Non-advanced: it changes what
/// the auditor can do, so it must be visible without `show advanced`.
pub(crate) fn taint_tools_option() -> OptionSpec {
    opt(
        "taintTools",
        OptionType::Enum,
        "Dataflow tools offered to the deep auditor: off, available (use an existing cpg graph), \
build (build the graph first). Unavailable graphs degrade to grep-only navigation.",
    )
    .aliases(&["taint_tools"])
    .choices(&["off", "available", "build"])
    .default(json!("available"))
}

fn triage_scope_option() -> OptionSpec {
    opt(
        "scope",
        OptionType::Enum,
        "Finding selection scope: `latest` triages the newest scan run only; `all` triages every \
untriaged finding across all runs and tools in the store (and defaults the strategy to `deep`).",
    )
    .choices(&["latest", "all"])
    .default(json!("latest"))
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

fn triage_dedupe_flag_option() -> OptionSpec {
    opt(
        "dedupe",
        OptionType::Bool,
        "Run the model-driven corpus dedupe (triage:dedupe) before triage so settled \
duplicates never burn triage spend. Opt-in.",
    )
    .default(json!(false))
}

fn triage_votes_option() -> OptionSpec {
    opt(
        "votes",
        OptionType::Int,
        "Independent triage passes per finding; a strict majority wins and disagreement downgrades to needs_review.",
    )
    .default(json!(1))
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

fn triage_strategy_option() -> OptionSpec {
    // No declared default: absence is meaningful — an unset strategy resolves
    // to `standard` for latest-scope runs and `deep` for scope=all bulk runs;
    // an explicit value always wins.
    opt(
        "strategy",
        OptionType::Enum,
        "Triage strategy. Unset defaults to standard (latest scope) or deep (scope=all).",
    )
    .choices(&["standard", "deep", "gate-deep"])
    .advanced()
}

fn deep_triage_options() -> OptionSpec {
    opt(
        "findingFingerprint",
        OptionType::String,
        "Fingerprint used by deep or gate-deep triage strategies.",
    )
    .aliases(&["finding_fingerprint"])
    .advanced()
}

fn deep_triage_advanced_options() -> Vec<OptionSpec> {
    vec![
        opt("maxSteps", OptionType::Int, "Deep triage step limit.")
            .aliases(&["max_steps"])
            .advanced(),
        opt(
            "depositUsd",
            OptionType::Float,
            "Deep triage spend deposit.",
        )
        .aliases(&["deposit_usd"])
        .advanced(),
        opt("passes", OptionType::Int, "Deep triage pass count.").advanced(),
        opt(
            "temperature",
            OptionType::Float,
            "Deep triage model temperature.",
        )
        .advanced(),
        opt(
            "targetPercentile",
            OptionType::Float,
            "Gate-deep classifier target percentile.",
        )
        .aliases(&["target_percentile"])
        .advanced(),
    ]
}

fn triage_prompt_option() -> OptionSpec {
    opt(
        "TRIAGE_PROMPT",
        OptionType::String,
        "Prompt text or path override for triage.",
    )
    .inline_or_workspace_file()
    .advanced()
}
