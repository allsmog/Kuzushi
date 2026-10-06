use super::*;

pub(super) fn approve_tool() -> ToolDescriptor {
    let mut tool = tool_with_options(
        "campaign:approve-allowance",
        "Approve exact provider-call limits for an investigation. Preserves consumed calls and unresolved reservations; starts no jobs. Dollar charges remain uncertain.",
        vec![
            investigation_option(),
            opt("expectedRevision", OptionType::Int, "Current allowance revision; zero for the first approval.").required().integer_range(0, i64::from(u32::MAX)),
            opt("model", OptionType::String, "Exact selected provider:model; no fallback.").required(),
            opt("maxProviderCalls", OptionType::Int, "Total calls including internal turns and retries across all phases.").required().integer_range(1, 1_000_000),
            opt("protectedReviewCalls", OptionType::Int, "Calls within the total protected for Review and Report.").required().integer_range(0, 1_000_000),
            opt("reason", OptionType::String, "Operator reason for approving these exact limits.").required(),
            opt("campaignId", OptionType::String, "Existing discovery or context study to bind as the finite work plan."),
            opt("campaignPlanSha256", OptionType::String, "Exact reviewed campaign plan digest; required with campaignId."),
            opt("campaignJobs", OptionType::Int, "Exact reviewed number of jobs; required with campaignId.").integer_range(1, 100),
            opt("maxJobAttempts", OptionType::Int, "Explicit attempts per job, including failed or canceled starts; required with campaignId.").integer_range(1, 10),
        ],
    ).with_policy(workspace_policy(ToolPhase::Map, RuntimeRequirement::Never, FindingStoreRequirement::Optional))
        .without_phase_result();
    tool.approval = ApprovalPolicy::Explicit;
    tool
}

pub(super) fn context_study_tool() -> ToolDescriptor {
    tool_with_options("campaign:context-study", "Draft one bounded Map model action for approval: source-grounded context or a scan scope proposal. Keeps current context and scope acceptance unchanged. Makes no model requests.", vec![
        opt("campaignId", OptionType::String, "New campaign identifier; generated when omitted."),
        investigation_option(),
        opt("generationTool", OptionType::Enum, "Model action for this fixed job. Scope proposals reuse an existing inventory and permit no preparation jobs.").choices(&["threat-model:build","pack:suggest-scopes"]).default(json!("threat-model:build")),
        opt("preparationJobs", OptionType::Json, "Optional ordered context:build and entry-points:extract jobs. At most one of each; prepared and approved with the context job."),
        opt("contextInput", OptionType::Json, "Options for the selected generation tool, checked through shared dispatch. No activation, scan jobs, recursive delegation or automatic follow-up work.").required(),
    ]).with_policy(workspace_policy(ToolPhase::Map, RuntimeRequirement::Never, FindingStoreRequirement::Optional)).without_phase_result()
}

pub(super) fn status_tool() -> ToolDescriptor {
    tool_with_options(
        "campaign:allowance",
        "Inspect an investigation's approved calls, protected review allocation and unresolved charges. Makes no model requests.",
        vec![investigation_option(), opt("runId", OptionType::String,
            "Optional admitted run whose provider-request counts to inspect. Missing legacy evidence remains unavailable; reading starts no work.").aliases(&["run_id"])],
    ).with_policy(read_policy(ToolPhase::Operate, WorkspaceRequirement::Required))
}

pub(super) fn context_map_tool() -> ToolDescriptor {
    tool_with_options(
        "campaign:context-map",
        "Record context-study jobs or an exact revision's authenticated producing run as a durable Map for review. Preserves partial status; starts no jobs or model requests and accepts nothing.",
        vec![
            opt("campaignId", OptionType::String, "Completed context study to review; requires expectedPlanSha256."),
            opt("expectedPlanSha256", OptionType::String, "Exact context plan digest; requires campaignId."),
            opt("threatModelRef", OptionType::Json, "Alternative to campaignId: exact immutable revision with an authenticated current-source producing run. Cannot combine with campaign fields.").aliases(&["threat_model_ref"]),
        ],
    )
    .with_policy(workspace_policy(ToolPhase::Map, RuntimeRequirement::Never, FindingStoreRequirement::Optional))
    .without_phase_result()
}

fn investigation_option() -> OptionSpec {
    opt(
        "investigationId",
        OptionType::String,
        "Investigation allowance identifier.",
    )
    .required()
}

pub(super) fn study_tool() -> ToolDescriptor {
    tool_with_options("campaign:study", "Draft a finite discovery scan batch for review. Defaults to three passes and one worker. Makes no model requests and starts no jobs.", vec![
        opt("campaignId", OptionType::String, "New campaign identifier; generated when omitted."),
        opt("investigationId", OptionType::String, "Investigation whose accounting this draft will retain. Defaults to the accepted Map's recorded investigation when available; an explicit identifier selects that investigation's accounting. Approval is still required for this exact plan."),
        opt("trials", OptionType::Int, "Number of fresh discovery passes in this fixed plan.").integer_range(2, 100).default(json!(3)),
        opt("workers", OptionType::Int, "Requested concurrency; engine safety may reduce it.").integer_range(1, 8).default(json!(1)),
        opt("baselineRunId", OptionType::String, "Explicit completed SAST run for historical usage evidence. Frozen as plan metadata; starts no work and grants no allowance.").aliases(&["baseline_run_id"]),
        opt("scanInput", OptionType::Json, "Options for sast:scan, checked through shared prepared dispatch; discovery only.").required(),
    ]).with_policy(workspace_policy(ToolPhase::Map, RuntimeRequirement::Never, FindingStoreRequirement::Optional)).without_phase_result()
}
