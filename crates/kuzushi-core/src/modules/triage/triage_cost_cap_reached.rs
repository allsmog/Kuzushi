use super::*;

pub(in crate::modules) fn triage_cost_cap_reached(
    cost_cap_usd: Option<f64>,
    total_cost: f64,
) -> bool {
    cost_cap_usd.is_some_and(|cap| total_cost >= cap)
}

pub(in crate::modules) fn call_triage_runtime(
    runtime: &dyn AgentRuntime,
    config: &TriageExecutionConfig,
    input: &TriageRunInput,
    finding: &Finding,
) -> Result<TriageOutcome> {
    runtime.triage_finding_blocking(TriageRequest {
        model: config.stage2_model.clone(),
        cwd: config.cwd.clone(),
        finding: finding.clone(),
        prompt_template: input.prompt_template.clone(),
    })
}

pub(in crate::modules) fn persist_triage_outcome(
    store: &FindingStore,
    stats: &mut TriageRunStats,
    finding: Finding,
    outcome: TriageOutcome,
) {
    let Some(finding_id) = finding.id else {
        stats.record_unpersisted_outcome(finding, outcome);
        return;
    };
    if let Err(error) = store.save_triage(finding_id, &outcome) {
        eprintln!(
            "[triage:run] could not persist triage for finding {}: {error}",
            finding.fingerprint
        );
    }
    stats.record_persisted_outcome(finding, outcome);
}

pub(in crate::modules) fn high_confidence_false_positive(result: &Value) -> bool {
    result.get("verdict").and_then(Value::as_str) == Some("false_positive")
        && result
            .get("confidence")
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
            >= 0.7
}

pub(in crate::modules) fn triage_response(
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    stage1: &PrefilteredTriageFindings,
    stats: &TriageRunStats,
    missing_fingerprints: Vec<String>,
) -> Value {
    let dropped_high_conf_fp = stats.high_confidence_false_positive_count();
    let summary = triage_summary(stage1, stats, &missing_fingerprints);
    let warnings = triage_warnings(stats, &missing_fingerprints);
    let data = triage_response_data(
        input,
        config,
        stage1,
        stats,
        missing_fingerprints,
        dropped_high_conf_fp,
        &summary,
    );
    json!({
        "ok": true,
        "status": "completed",
        "summary": summary,
        "output": summary,
        "artifacts": [],
        "warnings": warnings,
        "errors": [],
        "data": data,
        "costUsd": stats.total_cost,
    })
}

fn triage_response_data(
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    stage1: &PrefilteredTriageFindings,
    stats: &TriageRunStats,
    missing_fingerprints: Vec<String>,
    dropped_high_conf_fp: usize,
    summary: &str,
) -> Value {
    json!({
        "summary": summary,
        "triaged": stats.triaged(),
        "total": stage1.total,
        "tp": stats.tp,
        "fp": stats.fp,
        "needsReview": stats.needs_review,
        "byDesign": stats.by_design,
        "costUsd": stats.total_cost,
        "missingFingerprints": missing_fingerprints,
        "batchSize": input.batch_size,
        "concurrency": input.concurrency,
        "stage2Tier": triage_tier_label(input.stage2_tier),
        "costCapUsd": input.cost_cap_usd,
        "costCapHit": stats.cost_cap_hit,
        "pendingAfterCap": stats.pending_after_cap,
        "highConfidenceFalsePositivesDropped": dropped_high_conf_fp,
        "stages": triage_stages(input, config, stage1, stats, dropped_high_conf_fp),
        "results": stats.results,
        "findings": stats.results,
    })
}

fn triage_warnings(stats: &TriageRunStats, missing_fingerprints: &[String]) -> Vec<String> {
    let mut warnings = Vec::new();
    if stats.cost_cap_hit {
        warnings.push(format!(
            "Cost cap hit; {} finding(s) remain unevaluated.",
            stats.pending_after_cap
        ));
    }
    if !missing_fingerprints.is_empty() {
        warnings.push(format!(
            "{} requested finding(s) were not found.",
            missing_fingerprints.len()
        ));
    }
    warnings
}

pub(in crate::modules) fn triage_stages(
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    stage1: &PrefilteredTriageFindings,
    stats: &TriageRunStats,
    dropped_high_conf_fp: usize,
) -> Value {
    json!([
        {
            "stage": "prefilter",
            "kept": stage1.kept_count,
            "dropped": stage1.dropped,
            "rule": format!("prefilter_score >= {}", input.prefilter_threshold),
        },
        {
            "stage": "haiku",
            "model": config.stage2_model,
            "concurrency": input.concurrency,
            "triaged": stats.triaged(),
            "tp": stats.tp,
            "fp": stats.fp,
            "needsReview": stats.needs_review,
            "byDesign": stats.by_design,
            "highConfidenceFalsePositivesDropped": dropped_high_conf_fp,
            "costUsd": stats.total_cost,
            "costCapHit": stats.cost_cap_hit,
            "pendingAfterCap": stats.pending_after_cap,
        }
    ])
}
