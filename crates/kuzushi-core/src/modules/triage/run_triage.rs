use super::*;

#[cfg(test)]
mod tests;

pub(in crate::modules) fn run_triage(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = require_triage_workspace(ctx)?;
    crate::workspace::source_snapshot::run_source_bound_tool(
        ctx,
        "triage:run",
        workspace.root(),
        || run_triage_against_source(input, ctx, runtime),
    )
}

fn run_triage_against_source(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let mut run = prepare_triage_run(input, ctx)?;
    if run.findings.is_empty() {
        emit_triage_no_findings(ctx);
        let mut response = empty_triage_response(&run.input, run.missing_fingerprints);
        attach_triage_advisory_reports(&mut response, run.store, &run.input)?;
        return Ok(response);
    }
    let execution = resolve_triage_execution(ctx, runtime, &run)?;
    let completed = classify_triage_findings(&mut run, ctx, &execution)?;
    emit_triage_done(ctx, &completed.stats);
    let mut response = triage_response(
        &run.input,
        &execution.config,
        &completed.stage1,
        &completed.stats,
        run.missing_fingerprints,
    );
    attach_prefilter_drop_report(&mut response, &completed.prefilter_report);
    attach_triage_advisory_reports(&mut response, run.store, &run.input)?;
    Ok(response)
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
    let mut input = TriageRunInput::from_tool_input(&input, workspace.root())?;
    apply_threat_model_triage_context(&mut input, workspace.root())?;
    emit_triage_start(ctx, &input);
    let (findings, missing_fingerprints) = select_triage_findings(store, &input)?;
    input.suppression_feedback =
        suppression_feedback::suppression_feedback_notes(workspace, &findings)?;
    input.reviewed_refutation_priors =
        store.reviewed_refutation_priors_for(&findings, now_unix())?;
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
    /// Router-wrapped runtime for the deep (code-reading) classify path;
    /// built only when the run resolved `deep: true`.
    routed: Option<crate::agent_router::RoutedRuntime<'a>>,
    config: TriageExecutionConfig,
}

fn resolve_triage_execution<'a>(
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
    run: &PreparedTriageRun<'_>,
) -> Result<TriageExecution<'a>> {
    let runtime = require_triage_runtime(runtime)?;
    let stage2_model = resolve_triage_model(ctx, runtime, &run.input)?;
    let routed = if run.input.deep {
        Some(routed_runtime_for_tool_context(
            runtime,
            ctx,
            Some(run.workspace.root()),
        )?)
    } else {
        None
    };
    Ok(TriageExecution {
        runtime,
        routed,
        config: TriageExecutionConfig::new(run.workspace.root().to_path_buf(), stage2_model),
    })
}

struct CompletedTriageRun {
    stage1: PrefilteredTriageFindings,
    prefilter_report: PrefilterDropReport,
    stats: TriageRunStats,
}

fn classify_triage_findings(
    run: &mut PreparedTriageRun<'_>,
    ctx: &ToolExecutionContext<'_>,
    execution: &TriageExecution<'_>,
) -> Result<CompletedTriageRun> {
    let findings = std::mem::take(&mut run.findings);
    let (stage1, prefilter_report) =
        prefilter_triage_findings_with_receipts(findings, run.input.prefilter_threshold);
    let evidence_phase = emit_triage_evidence_phase(ctx, &run.input, &stage1);
    let kept = stage1.kept.clone();
    let stats = run_triage_stage2_with_scope(ctx, evidence_phase, run, execution, kept)?;
    Ok(CompletedTriageRun {
        stage1,
        prefilter_report,
        stats,
    })
}

fn run_triage_stage2_with_scope(
    ctx: &ToolExecutionContext<'_>,
    evidence_phase: Option<crate::run_lifecycle::RunItemId>,
    run: &PreparedTriageRun<'_>,
    execution: &TriageExecution<'_>,
    kept: Vec<Finding>,
) -> Result<TriageRunStats> {
    let _llm_scope = begin_triage_llm_scope(ctx, evidence_phase);
    let stats = match &execution.routed {
        Some(routed) => run_triage_stage2_deep(
            run.store,
            routed,
            &run.input,
            &execution.config,
            kept,
            ctx.trace,
        )?,
        None => run_triage_stage2(
            run.store,
            execution.runtime,
            &run.input,
            &execution.config,
            kept,
        )?,
    };
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
) -> Option<crate::run_lifecycle::RunItemId> {
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
    evidence_phase: Option<crate::run_lifecycle::RunItemId>,
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
        let cost = stats.cost_report();
        let label = triage_done_label(stats, cost);
        let _ = trace.step("done", "run", label).emit();
    }
}

fn triage_done_label(stats: &TriageRunStats, cost: crate::runtime::RuntimeCostReport) -> String {
    let unresolved = if cost.is_complete() {
        String::new()
    } else if let Some(estimate) = cost.estimated_total_usd() {
        format!(" · estimated cost ~${estimate:.4} (provider reported no charge)")
    } else {
        format!(
            " · provider spend unresolved (observed ${:.4})",
            cost.observed_usd()
        )
    };
    format!(
        "triage-finish · classifications={}/{} failed={} voteFailures={} persistenceFailures={} · tp={} fp={} review={} byDesign={}{}",
        stats.successful,
        stats.attempted,
        stats.failed,
        stats.vote_failures,
        stats.persistence_failures,
        stats.tp,
        stats.fp,
        stats.needs_review,
        stats.by_design,
        unresolved,
    )
}

pub(in crate::modules) fn require_triage_workspace<'a>(
    ctx: &'a ToolExecutionContext<'_>,
) -> Result<&'a WorkspaceTarget> {
    ctx.workspace
        .context(crate::workspace::active_workspace_required_message(
            "triage:run",
        ))
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
    let summary = "No findings matched triage input.";
    let output = "[-] No findings match. Run a scanner first (`kuzushi scan <repo>`) or pass explicit fingerprints.";
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
        "policies": {
            "identityReconcile": input.identity_reconcile.as_str(),
            "modelDedupe": model_dedupe_receipt(input.model_dedupe),
            "occurrenceEvidence": occurrence_evidence_receipt(),
        },
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

pub(in crate::modules) fn attach_triage_advisory_reports(
    response: &mut Value,
    store: &FindingStore,
    input: &TriageRunInput,
) -> Result<()> {
    let findings = store.list_all_findings()?;
    let clusters = crate::findings::derive_cross_tool_cluster_report(&findings);
    let refutation = store.reviewed_refutation_report(now_unix())?;
    let cluster_count = clusters.candidate_clusters.len();
    let plain_lines = refutation_plain_lines(&refutation);
    insert_advisory_data(response, input, clusters, refutation)?;
    append_advisory_output(response, cluster_count, &plain_lines);
    Ok(())
}

fn insert_advisory_data(
    response: &mut Value,
    input: &TriageRunInput,
    clusters: crate::findings::CrossToolClusterReport,
    refutation: crate::findings::ReviewedRefutationReport,
) -> Result<()> {
    let data = response
        .get_mut("data")
        .and_then(Value::as_object_mut)
        .context("triage response is missing its data object")?;
    data.insert(
        "crossToolClusters".to_string(),
        serde_json::to_value(clusters)?,
    );
    data.insert(
        "reviewedRefutation".to_string(),
        serde_json::to_value(refutation)?,
    );
    data.insert(
        "policies".to_string(),
        json!({
            "identityReconcile": input.identity_reconcile.as_str(),
            "modelDedupe": model_dedupe_receipt(input.model_dedupe),
            "occurrenceEvidence": occurrence_evidence_receipt(),
        }),
    );
    Ok(())
}

fn model_dedupe_receipt(policy: ModelDedupePolicy) -> Value {
    match policy {
        ModelDedupePolicy::Off => json!({
            "mode": "off",
            "prepassExecuted": false,
        }),
        ModelDedupePolicy::Manual => json!({
            "mode": "manual",
            "prepassExecuted": false,
            "nextAction": "run triage:dedupe dryRun=true to inspect model proposals",
        }),
        ModelDedupePolicy::Auto => json!({
            "mode": "auto",
            "prepassExecuted": true,
        }),
    }
}

fn occurrence_evidence_receipt() -> Value {
    json!({
        "presence": "corroboration_only",
        "absence": "not_refutation",
        "breaksTiedVerdict": false,
    })
}

fn append_advisory_output(response: &mut Value, clusters: usize, lines: &[String]) {
    let Some(output) = response.get_mut("output") else {
        return;
    };
    let mut rendered = output.as_str().unwrap_or_default().to_string();
    rendered.push_str(&format!(
        "\nCross-tool candidates: {clusters} cluster(s), report only; no verdict inheritance."
    ));
    for line in lines {
        rendered.push('\n');
        rendered.push_str(line);
    }
    *output = json!(rendered);
}

fn refutation_plain_lines(report: &crate::findings::ReviewedRefutationReport) -> Vec<String> {
    report
        .populations
        .iter()
        .filter(|stats| {
            matches!(
                stats.population,
                crate::findings::RefutationPopulation::Human
                    | crate::findings::RefutationPopulation::Automatic
            )
        })
        .map(refutation_population_line)
        .collect()
}

fn refutation_population_line(stats: &crate::findings::RefutationPopulationStats) -> String {
    let population = match stats.population {
        crate::findings::RefutationPopulation::Human => "human",
        crate::findings::RefutationPopulation::Automatic => "automatic",
        crate::findings::RefutationPopulation::Imported => "imported",
    };
    let observed = stats
        .observed_refutation_rate
        .map(percent_label)
        .unwrap_or_else(|| "n/a".to_string());
    format!(
        "Reviewed refutation ({population}): {observed} ({}/{} reviewed; {}/{} emitted) · Beta(1,1) shrunken {}, 90% interval {}–{}.",
        stats.refuted,
        stats.reviewed,
        stats.reviewed,
        stats.emitted,
        percent_label(stats.shrunken_refutation_rate),
        percent_label(stats.credible_interval_90[0]),
        percent_label(stats.credible_interval_90[1]),
    )
}

fn percent_label(rate: f64) -> String {
    format!("{:.0}%", (rate * 100.0).clamp(0.0, 100.0))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
    input: &TriageRunInput,
) -> Result<String> {
    let configured = crate::runtime::resolve_explicit_model(
        "triage:run",
        input.model.clone(),
        ctx.config.model.as_deref(),
    )?;
    let model = runtime.model_for_tier(input.stage2_tier, &configured);
    crate::runtime::validate_model_spec(&model)
        .with_context(|| "triage:run resolved an invalid stage2 model")?;
    Ok(model)
}

const PREFILTER_DROP_RECEIPT_LIMIT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrefilterDropReceipt {
    finding_id: Option<i64>,
    identity_id: Option<String>,
    score: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrefilterDropReport {
    threshold: i64,
    total: usize,
    receipts: Vec<PrefilterDropReceipt>,
    omitted: usize,
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
    prefilter_triage_findings_with_receipts(findings, prefilter_threshold).0
}

fn prefilter_triage_findings_with_receipts(
    findings: Vec<Finding>,
    prefilter_threshold: i64,
) -> (PrefilteredTriageFindings, PrefilterDropReport) {
    let total = findings.len();
    let mut kept = Vec::with_capacity(total);
    let mut dropped = 0usize;
    let mut receipts = Vec::new();
    let mut omitted = 0usize;

    for finding in findings {
        let score = prefilter_score(&finding);
        if score >= prefilter_threshold {
            kept.push(finding);
            continue;
        }

        dropped += 1;
        if receipts.len() < PREFILTER_DROP_RECEIPT_LIMIT {
            receipts.push(PrefilterDropReceipt {
                finding_id: finding.id,
                identity_id: finding.identity_id.clone(),
                score,
            });
        } else {
            omitted += 1;
        }
    }

    let kept_count = kept.len();
    (
        PrefilteredTriageFindings {
            total,
            kept_count,
            dropped,
            kept,
        },
        PrefilterDropReport {
            threshold: prefilter_threshold,
            total: dropped,
            receipts,
            omitted,
        },
    )
}

fn attach_prefilter_drop_report(response: &mut Value, report: &PrefilterDropReport) {
    let Some(data) = response.get_mut("data").and_then(Value::as_object_mut) else {
        return;
    };
    let items = report
        .receipts
        .iter()
        .map(|receipt| {
            json!({
                "findingId": receipt.finding_id,
                "identityId": receipt.identity_id,
                "score": receipt.score,
                "reason": "prefilter_score_below_threshold",
            })
        })
        .collect::<Vec<_>>();
    data.insert(
        "prefilterDrops".to_string(),
        json!({
            "count": report.total,
            "threshold": report.threshold,
            "items": items,
            "omitted": report.omitted,
            "limit": PREFILTER_DROP_RECEIPT_LIMIT,
        }),
    );
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

#[cfg(test)]
mod prefilter_drop_receipt_tests {
    use super::*;

    #[test]
    fn prefilter_drop_report_is_itemized_and_bounded() {
        let findings = (0..(PREFILTER_DROP_RECEIPT_LIMIT + 3))
            .map(|index| {
                let mut finding = Finding::new_tool(
                    "other",
                    format!("rule-{index}"),
                    "src/lib.rs",
                    index as u32 + 1,
                    None,
                    Severity::Unknown,
                    format!("plain finding {index}"),
                );
                finding.id = Some(index as i64 + 1);
                finding.identity_id = Some(format!("identity-{index}"));
                finding
            })
            .collect::<Vec<_>>();

        let (stage1, report) = prefilter_triage_findings_with_receipts(findings, 5);

        assert_eq!(stage1.total, PREFILTER_DROP_RECEIPT_LIMIT + 3);
        assert_eq!(stage1.kept_count, 0);
        assert_eq!(stage1.dropped, PREFILTER_DROP_RECEIPT_LIMIT + 3);
        assert_eq!(report.total, PREFILTER_DROP_RECEIPT_LIMIT + 3);
        assert_eq!(report.receipts.len(), PREFILTER_DROP_RECEIPT_LIMIT);
        assert_eq!(report.omitted, 3);
        assert!(report
            .receipts
            .iter()
            .all(|receipt| receipt.score < report.threshold));
        assert_eq!(report.receipts[0].finding_id, Some(1));
        assert_eq!(
            report.receipts[0].identity_id.as_deref(),
            Some("identity-0")
        );

        let mut response = json!({"data": {}});
        attach_prefilter_drop_report(&mut response, &report);

        assert_eq!(
            response["data"]["prefilterDrops"]["count"],
            json!(PREFILTER_DROP_RECEIPT_LIMIT + 3)
        );
        assert_eq!(
            response["data"]["prefilterDrops"]["items"]
                .as_array()
                .unwrap()
                .len(),
            PREFILTER_DROP_RECEIPT_LIMIT
        );
        assert_eq!(response["data"]["prefilterDrops"]["omitted"], json!(3));
        assert_eq!(
            response["data"]["prefilterDrops"]["items"][0]["reason"],
            json!("prefilter_score_below_threshold")
        );
        assert_eq!(response["data"]["prefilterDrops"]["threshold"], json!(5));
    }
}
