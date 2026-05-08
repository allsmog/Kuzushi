use super::*;

pub(in crate::modules) fn run_triage(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = require_triage_workspace(ctx)?;
    let store = require_triage_store(ctx)?;
    let input = TriageRunInput::from_tool_input(&input, workspace.root())?;
    let (findings, missing_fingerprints) = select_triage_findings(store, &input)?;
    if findings.is_empty() {
        return Ok(empty_triage_response(&input, missing_fingerprints));
    }

    let runtime = require_triage_runtime(runtime)?;
    let stage2_model = resolve_triage_model(ctx, runtime, input.stage2_tier)?;
    let mut stage1 = prefilter_triage_findings(findings, input.prefilter_threshold);
    let config = TriageExecutionConfig::new(workspace.root().to_path_buf(), stage2_model);
    let kept = std::mem::take(&mut stage1.kept);
    let stats = run_triage_stage2(store, runtime, &input, &config, kept)?;
    Ok(triage_response(
        &input,
        &config,
        &stage1,
        &stats,
        missing_fingerprints,
    ))
}

pub(in crate::modules) fn require_triage_workspace<'a>(
    ctx: &'a ToolExecutionContext<'_>,
) -> Result<&'a WorkspaceTarget> {
    ctx.workspace.context(
        "triage:run needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )
}

pub(in crate::modules) fn require_triage_store<'a>(
    ctx: &'a ToolExecutionContext<'_>,
) -> Result<&'a FindingStore> {
    ctx.findings_store
        .context("triage:run requires a findings store for the active workspace")
}

pub(in crate::modules) fn empty_triage_response(
    input: &TriageRunInput,
    missing_fingerprints: Vec<String>,
) -> Value {
    json!({
        "ok": false,
        "output": "[-] No findings match. Run a scanner first (`kuzushi scan <repo>`) or pass explicit fingerprints.",
        "data": {
            "triaged": 0,
            "total": 0,
            "tp": 0,
            "fp": 0,
            "needsReview": 0,
            "byDesign": 0,
            "costUsd": 0.0,
            "missingFingerprints": missing_fingerprints,
            "batchSize": input.batch_size,
        },
        "costUsd": 0.0,
    })
}

pub(in crate::modules) fn require_triage_runtime(
    runtime: Option<&dyn AgentRuntime>,
) -> Result<&dyn AgentRuntime> {
    runtime.context(
        "triage:run requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )
}

pub(in crate::modules) fn resolve_triage_model(
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
    tier: ModelTier,
) -> Result<String> {
    let model_configured = ctx.config.model.clone().context(
        "triage:run requires an explicit model in config.toml or KUZUSHI_MODEL; Kuzushi will not choose a fallback model",
    )?;
    Ok(runtime.model_for_tier(tier, &model_configured))
}

pub(in crate::modules) struct PrefilteredTriageFindings {
    pub(in crate::modules) total: usize,
    pub(in crate::modules) kept_count: usize,
    pub(in crate::modules) kept: Vec<Finding>,
    pub(in crate::modules) dropped: usize,
}

pub(in crate::modules) fn prefilter_triage_findings(
    findings: Vec<Finding>,
    prefilter_threshold: i64,
) -> PrefilteredTriageFindings {
    let total = findings.len();
    let (kept, dropped): (Vec<Finding>, Vec<Finding>) = findings
        .into_iter()
        .partition(|finding| prefilter_score(finding) >= prefilter_threshold);
    let kept_count = kept.len();
    PrefilteredTriageFindings {
        total,
        kept_count,
        dropped: dropped.len(),
        kept,
    }
}

pub(in crate::modules) struct TriageExecutionConfig {
    pub(in crate::modules) cwd: PathBuf,
    pub(in crate::modules) stage2_model: String,
}

impl TriageExecutionConfig {
    pub(in crate::modules) fn new(cwd: PathBuf, stage2_model: String) -> Self {
        Self { cwd, stage2_model }
    }
}
