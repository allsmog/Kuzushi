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
