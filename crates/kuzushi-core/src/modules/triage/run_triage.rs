use super::*;

pub(in crate::modules) fn run_triage(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let mut run = prepare_triage_run(input, ctx)?;
    if run.findings.is_empty() {
        emit_triage_no_findings(ctx);
        return Ok(empty_triage_response(&run.input, run.missing_fingerprints));
    }
    let execution = resolve_triage_execution(ctx, runtime, &run)?;
    let completed = classify_triage_findings(&mut run, ctx, &execution)?;
    emit_triage_done(ctx, &completed.stats);
    Ok(triage_response(
        &run.input,
        &execution.config,
        &completed.stage1,
        &completed.stats,
        run.missing_fingerprints,
    ))
}

struct PreparedTriageRun<'a> {
    workspace: &'a WorkspaceTarget,
    store: &'a FindingStore,
    input: TriageRunInput,
    findings: Vec<Finding>,
    missing_fingerprints: Vec<String>,
}

fn prepare_triage_run<'a>(
    input: Value,
    ctx: &'a ToolExecutionContext<'_>,
) -> Result<PreparedTriageRun<'a>> {
    let workspace = require_triage_workspace(ctx)?;
    let store = require_triage_store(ctx)?;
    let input = TriageRunInput::from_tool_input(&input, workspace.root())?;
    emit_triage_start(ctx, &input);
    let (findings, missing_fingerprints) = select_triage_findings(store, &input)?;
    emit_triage_loaded(ctx, findings.len(), missing_fingerprints.len());
    Ok(PreparedTriageRun {
        workspace,
        store,
        input,
        findings,
        missing_fingerprints,
    })
}

struct TriageExecution<'a> {
    runtime: &'a dyn AgentRuntime,
    config: TriageExecutionConfig,
}

fn resolve_triage_execution<'a>(
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
    run: &PreparedTriageRun<'_>,
) -> Result<TriageExecution<'a>> {
    let runtime = require_triage_runtime(runtime)?;
    let stage2_model = resolve_triage_model(ctx, runtime, run.input.stage2_tier)?;
    Ok(TriageExecution {
        runtime,
        config: TriageExecutionConfig::new(run.workspace.root().to_path_buf(), stage2_model),
    })
}

struct CompletedTriageRun {
    stage1: PrefilteredTriageFindings,
    stats: TriageRunStats,
}

fn classify_triage_findings(
    run: &mut PreparedTriageRun<'_>,
    ctx: &ToolExecutionContext<'_>,
    execution: &TriageExecution<'_>,
) -> Result<CompletedTriageRun> {
    let findings = std::mem::take(&mut run.findings);
    let mut stage1 = prefilter_triage_findings(findings, run.input.prefilter_threshold);
    let evidence_phase = emit_triage_evidence_phase(ctx, &run.input, &stage1);
    let kept = std::mem::take(&mut stage1.kept);
    let stats = run_triage_stage2_with_scope(ctx, evidence_phase, run, execution, kept)?;
    Ok(CompletedTriageRun { stage1, stats })
}

fn run_triage_stage2_with_scope(
    ctx: &ToolExecutionContext<'_>,
    evidence_phase: Option<usize>,
    run: &PreparedTriageRun<'_>,
    execution: &TriageExecution<'_>,
    kept: Vec<Finding>,
) -> Result<TriageRunStats> {
    let _llm_scope = begin_triage_llm_scope(ctx, evidence_phase);
    let stats = run_triage_stage2(
        run.store,
        execution.runtime,
        &run.input,
        &execution.config,
        kept,
    )?;
    drop(_llm_scope);
    Ok(stats)
}

fn emit_triage_start(ctx: &ToolExecutionContext<'_>, input: &TriageRunInput) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "run",
                format!("triage start (concurrency={})", input.concurrency),
            )
            .emit();
    }
}

fn emit_triage_loaded(ctx: &ToolExecutionContext<'_>, found: usize, missing: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "run",
                format!("load-finding · {found} candidates ({missing} missing)"),
            )
            .emit();
    }
}

fn emit_triage_no_findings(ctx: &ToolExecutionContext<'_>) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step("done", "run", "no findings to triage").emit();
    }
}

fn emit_triage_evidence_phase(
    ctx: &ToolExecutionContext<'_>,
    input: &TriageRunInput,
    stage1: &PrefilteredTriageFindings,
) -> Option<usize> {
    ctx.trace.map(|trace| {
        trace
            .step(
                "reasoning",
                "run",
                format!(
                    "evidence-collect · stage1 kept {kept}/{total} (threshold {threshold})",
                    kept = stage1.kept_count,
                    total = stage1.total,
                    threshold = input.prefilter_threshold,
                ),
            )
            .emit()
    })
}

fn begin_triage_llm_scope(
    ctx: &ToolExecutionContext<'_>,
    evidence_phase: Option<usize>,
) -> Option<crate::run_artifacts::ParentScope> {
    match (ctx.trace, evidence_phase) {
        (Some(trace), Some(_parent)) => {
            let phase_n = trace.step("reasoning", "run", "llm-classify").emit();
            Some(trace.parent_scope(phase_n))
        }
        _ => None,
    }
}

fn emit_triage_done(ctx: &ToolExecutionContext<'_>, stats: &TriageRunStats) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "run",
                format!(
                    "verdict-write · tp={} fp={} review={} byDesign={}",
                    stats.tp, stats.fp, stats.needs_review, stats.by_design,
                ),
            )
            .with_cost_usd(stats.total_cost)
            .emit();
    }
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
    _input: &TriageRunInput,
    missing_fingerprints: Vec<String>,
) -> Value {
    let summary = "No findings matched triage input.";
    let output =
        "[-] No findings match. Run a scanner first (`kuzushi scan <repo>`) or pass explicit fingerprints.";
    let data = json!({
        "summary": "No findings matched triage input.",
        "triaged": 0,
        "total": 0,
        "tp": 0,
        "fp": 0,
        "needsReview": 0,
        "byDesign": 0,
        "costUsd": 0.0,
        "missingFingerprints": missing_fingerprints,
        "findings": [],
    });
    let mut result = crate::module_result::skipped_output_result(
        summary,
        output,
        vec![json!("No findings matched triage input.")],
        data,
    );
    result["costUsd"] = json!(0.0);
    result
}

pub(in crate::modules) fn require_triage_runtime(
    runtime: Option<&dyn AgentRuntime>,
) -> Result<&dyn AgentRuntime> {
    runtime.context(
        "triage:run requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
    )
}

pub(in crate::modules) fn resolve_triage_model(
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
    tier: ModelTier,
) -> Result<String> {
    let model_configured =
        crate::runtime::require_configured_model("triage:run", ctx.config.model.as_deref())?;
    let model = runtime.model_for_tier(tier, &model_configured);
    crate::runtime::validate_model_spec(&model)
        .with_context(|| "triage:run resolved an invalid stage2 model")?;
    Ok(model)
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
