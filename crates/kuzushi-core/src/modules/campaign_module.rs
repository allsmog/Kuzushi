use super::*;

mod allowance;

pub(crate) fn campaign_module() -> BuiltinModule {
    builtin_module(
        "campaign",
        "Campaign",
        ModuleKind::Intel,
        "Plan and track multi-job scan campaigns over threat-model, shard, and model axes.",
        vec![
            allowance::study_tool(),
            allowance::approve_tool(),
            allowance::status_tool(),
            campaign_plan_tool().with_policy(workspace_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            )),
            // Workspace-write: besides folding status, every run appends a
            // deduped trend snapshot to `.kuzushi/trend-history.jsonl`. The
            // store must open so the workspace trend (FP rate from review
            // decisions) folds identically headless and in the shell — same
            // requirement `campaign:coverage` carries.
            campaign_status_tool().with_policy(workspace_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            )),
            campaign_coverage_tool().with_policy(workspace_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            )),
        ],
        vec![],
    )
}

fn campaign_plan_tool() -> ToolDescriptor {
    tool_with_options(
        "campaign:plan",
        "Deterministically cross the threat model (or a modelsDir of subsystem \
         models) with the shard manifest and optional model list into a ranked \
         job matrix at .kuzushi/v3/campaigns/<id>/plan.json, with one seasoned \
         prompt file per threat-scoped job. No model calls.",
        campaign_plan_options(),
    )
}

fn campaign_plan_options() -> Vec<OptionSpec> {
    let mut options = vec![
        opt("campaignId", OptionType::String, "Campaign identifier.")
            .aliases(&["campaign_id", "id"]),
        opt("tool", OptionType::String, "Tool each planned job runs.")
            .default(json!("sast:scan")),
        opt(
            "shards",
            OptionType::StringList,
            "Shard names from .kuzushi/shards.toml to include. Default: all.",
        ),
        opt(
            "models",
            OptionType::StringList,
            "Model axis; one job variant per model. Default: workspace model.",
        ),
    ];
    options.extend(campaign_plan_shape_options());
    options
}

fn campaign_plan_shape_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "maxJobs",
            OptionType::Int,
            "Job-matrix cap; overflow is dropped lowest-priority-first and reported.",
        )
        .aliases(&["max_jobs"])
        .default(json!(64)),
        opt(
            "modelsDir",
            OptionType::Path,
            "Directory of subsystem threat-model JSON documents to compound \
             instead of the single workspace threat model.",
        )
        .aliases(&["models_dir"])
        .external_read()
        .advanced(),
        opt(
            "seasonPrompts",
            OptionType::Bool,
            "Write a per-threat-job prompt override (default triage prompt + campaign focus).",
        )
        .aliases(&["season_prompts"])
        .default(json!(true))
        .advanced(),
        opt(
            "promptOption",
            OptionType::String,
            "Tool option name that receives the seasoned prompt path.",
        )
        .aliases(&["prompt_option"])
        .default(json!("TRIAGE_PROMPT"))
        .advanced(),
        opt(
            "fillGaps",
            OptionType::Bool,
            "Skip shard × threat-source cells the coverage fold already \
             reports completed or running, so re-planning converges on gaps.",
        )
        .aliases(&["fill_gaps"])
        .default(json!(false)),
        opt(
            "allowUnseasoned",
            OptionType::Bool,
            "Plan unseasoned jobs even when a present threat document \
             contains no threats[] (e.g. a pack context distillation), \
             instead of erroring. The skipped documents are named in the \
             result.",
        )
        .aliases(&["allow_unseasoned"])
        .default(json!(false))
        .advanced(),
    ]
}

fn campaign_coverage_tool() -> ToolDescriptor {
    tool_with_options(
        "campaign:coverage",
        "Coverage matrix: shards × threat sources with per-cell campaign \
         progress and per-shard finding counts. Read-only; no model calls.",
        vec![],
    )
}

fn campaign_status_tool() -> ToolDescriptor {
    tool_with_options(
        "campaign:status",
        "Fold a campaign plan with the dispatcher queue and run done.json \
         sentinels into one status view; without campaignId, list all campaigns.",
        vec![opt(
            "campaignId",
            OptionType::String,
            "Campaign to inspect. Omit to list every campaign.",
        )
        .aliases(&["campaign_id", "id"])],
    )
}
