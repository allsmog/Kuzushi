use super::*;

pub(super) fn approve_tool() -> ToolDescriptor {
    let mut tool = tool_with_options(
        "campaign:approve-allowance",
        "Approve exact provider-call limits for an investigation. Preserves consumed calls and unresolved reservations; starts no jobs. Dollar charges remain uncertain.",
        vec![
            investigation_option(),
            opt("expectedRevision", OptionType::Int, "Current allowance revision; zero for the first approval.").required().integer_range(0, i64::from(u32::MAX)),
            opt("model", OptionType::String, "Exact selected provider:model; no fallback.").required(),
            opt("maxProviderCalls", OptionType::Int, "Total calls including internal turns and retries across all phases. Zero forbids every provider request.").required().integer_range(0, 1_000_000),
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
    tool_with_options("campaign:context-study", "Draft one bounded model action for approval: context, scan scopes or a lesson. Keeps context, scope and lesson acceptance unchanged. Makes no model requests.", vec![
        opt("campaignId", OptionType::String, "New campaign identifier; generated when omitted."),
        investigation_option(),
        opt("generationTool", OptionType::Enum, "Model action for this fixed job. Scope proposals, selective context regeneration, context questions, workflow proposals and lesson drafts permit no preparation jobs.").choices(&["threat-model:build","pack:suggest-scopes","threat-model:regenerate","threat-model:ask","planner:propose","findings:lesson-generate"]).default(json!("threat-model:build")),
        opt("preparationJobs", OptionType::Json, "Optional ordered context:build and entry-points:extract jobs. At most one of each; prepared and approved with the context job."),
        opt("contextInput", OptionType::Json, "Options for the selected generation tool, checked through shared dispatch. No activation, scan jobs, recursive delegation or automatic follow-up work.").required(),
        brief_option(),
        opt("useBriefGuidance", OptionType::Bool, "Explicitly supply the selected briefRef to a fresh inactive repository or file-group context build. Entire reviewed text is supplied as priorities, not source evidence. Requires separate plan/allowance approval.").default(json!(false)),
        opt("scopeStudyOrigin", OptionType::Json, "Versioned local scope study draft to resume after file-group context generation. Retains scope and context choices; grants no discovery jobs or approval.").aliases(&["scope_study_origin"]).advanced(),
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

pub(super) fn review_study_tool() -> ToolDescriptor {
    tool_with_options("campaign:review-study", "Draft one bounded review job over exact finding observations. Preserves the selected review strategy. Approval and execution are separate; no model requests or jobs start.", vec![
        opt("campaignId", OptionType::String, "New campaign identifier; generated when omitted."),
        investigation_option(),
        opt("reviewInput", OptionType::Json, "Declared triage:run options. Freezes 1 to 100 selected observations, one worker and the effective review strategy. Internal calls and retries share the approved Review allowance.").required(),
    ]).with_policy(workspace_policy(ToolPhase::Review, RuntimeRequirement::Never, FindingStoreRequirement::Required)).without_phase_result()
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
        brief_option(),
        opt("investigationId", OptionType::String, "Investigation whose accounting this draft will retain. Defaults to the accepted Map's recorded investigation when available; an explicit identifier selects that investigation's accounting. Approval is still required for this exact plan."),
        opt("trials", OptionType::Int, "Number of fresh discovery passes in this fixed plan.").integer_range(2, 100).default(json!(3)),
        opt("workers", OptionType::Int, "Requested concurrency; engine safety may reduce it.").integer_range(1, 8).default(json!(1)),
        opt("baselineRunId", OptionType::String, "Explicit completed SAST run for historical usage evidence. Frozen as plan metadata; starts no work and grants no allowance.").aliases(&["baseline_run_id"]),
        opt("resourceBaselineCampaignId", OptionType::String, "Explicit prior scope study or context matrix for bounded, per-case historical usage evidence. Requires scopeCases or contextCases; cannot combine with baselineRunId. Only matching complete child runs calibrate a case. Missing prices and uncalibrated cases remain unknown.").aliases(&["resource_baseline_campaign_id"]).advanced(),
        opt("contextBaselineRunId", OptionType::String, "Explicit completed SAST run to compare with this candidate context. Source, scope, scan options, model and runtime must match; only the exact context may differ. Each candidate remains a separately approved fixed study.").aliases(&["context_baseline_run_id"]),
        opt("contextCases", OptionType::Json, "Optional finite context matrix: two to eight objects with id, label, exact threatModelRef (or explicit null), and optional passes. Missing passes inherit trials. Total work is at most 100 fixed jobs; all cases share one allowance and otherwise identical scan conditions.").aliases(&["context_cases"]),
        opt("baselineCaseId", OptionType::String, "Explicit baseline case id required with contextCases. Fresh baseline repetitions are included in this matrix's approved workload.").aliases(&["baseline_case_id"]),
        opt("scopeProposalRef", OptionType::Json, "Exact accepted scope proposal for a finite multi-scope study. Requires scopeCases; cannot combine with context experiments or scanInput.scanScopeRef.").aliases(&["scope_proposal_ref"]),
        opt("scopeCases", OptionType::Json, "One to nine explicit objects with scopeId, optional passes, and optional exact threatModelRef override or null. Missing passes inherit trials; missing context inherits the common accepted context. At most 100 fixed jobs, one shared allowance, no recursive subdivision.").aliases(&["scope_cases"]),
        opt("scanInput", OptionType::Json, "Options for sast:scan, checked through shared prepared dispatch; discovery only.").required(),
    ]).with_policy(workspace_policy(ToolPhase::Map, RuntimeRequirement::Never, FindingStoreRequirement::Optional)).without_phase_result()
}

fn brief_option() -> OptionSpec {
    opt("briefRef", OptionType::Json, "Exact accepted operator brief revision to retain with this plan. It guides human planning and priorities; it changes no scanner prompt, finding verdict, job count or allowance.")
}
