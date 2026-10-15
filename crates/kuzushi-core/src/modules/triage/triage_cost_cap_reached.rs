use super::*;
#[derive(Clone)]
pub(in crate::modules) struct TriageRuntimeOutcome {
    pub(in crate::modules) outcome: TriageOutcome,
    pub(in crate::modules) cached: bool,
    pub(in crate::modules) failed_vote_summaries: Vec<String>,
    /// Deep-auditor evidence citations for the representative finding. Empty
    /// for the standard single-shot path and for inherited duplicates.
    pub(in crate::modules) evidence: Vec<crate::capabilities::deep_auditor::EvidenceCitation>,
}

pub(in crate::modules) fn triage_cost_cap_reached(
    cost_cap_usd: Option<f64>,
    cost: crate::runtime::RuntimeCostReport,
) -> bool {
    // Unmetered spend counts at its labelled estimate; spend with no estimate
    // at all is unbounded, so the cap fails closed.
    cost_cap_usd.is_some_and(|cap| cost.estimated_total_usd().is_none_or(|spent| spent >= cap))
}

pub(in crate::modules) fn call_triage_runtime(
    runtime: &dyn AgentRuntime,
    config: &TriageExecutionConfig,
    input: &TriageRunInput,
    finding: &Finding,
) -> Result<TriageRuntimeOutcome> {
    let request = TriageRequest {
        model: config.stage2_model.clone(),
        cwd: config.cwd.clone(),
        finding: finding.clone(),
        prompt_template: triage_prompt_with_grounding(input, finding),
    };
    let key = runtime_cache::key(
        &request,
        config.source_snapshot.as_deref(),
        runtime.triage_semantic_cache_identity(&request),
    )?;
    if let Some(outcome) = runtime_cache::reusable_outcome(key.as_ref(), input.retriage) {
        return Ok(TriageRuntimeOutcome {
            outcome,
            cached: true,
            failed_vote_summaries: Vec::new(),
            evidence: Vec::new(),
        });
    }
    let outcome = crate::runtime::triage_finding_blocking_checked(runtime, request)?;
    runtime_cache::remember(key, outcome.clone());
    Ok(TriageRuntimeOutcome {
        outcome,
        cached: false,
        failed_vote_summaries: Vec::new(),
        evidence: Vec::new(),
    })
}

/// One additional consensus vote. Deliberately bypasses the runtime cache in
/// both directions: reading it would replay vote #1 verbatim (defeating vote
/// independence), and writing it would let a later single-vote run pick up
/// an arbitrary vote instead of the consensus.
pub(in crate::modules) fn call_triage_runtime_uncached(
    runtime: &dyn AgentRuntime,
    config: &TriageExecutionConfig,
    input: &TriageRunInput,
    finding: &Finding,
) -> Result<TriageOutcome> {
    let request = TriageRequest {
        model: config.stage2_model.clone(),
        cwd: config.cwd.clone(),
        finding: finding.clone(),
        prompt_template: triage_prompt_with_grounding(input, finding),
    };
    crate::runtime::triage_finding_blocking_checked(runtime, request)
}

/// Appends per-finding honesty notes to the triage prompt: a grounding note
/// for imported findings with stale anchors (re-check the citation instead of
/// trusting it), and stored-suppression reviewer feedback (data, not
/// instructions — dismiss only if the recorded reason still applies).
fn triage_prompt_with_grounding(input: &TriageRunInput, finding: &Finding) -> Option<String> {
    let notes = triage_prompt_notes(input, finding);
    if notes.is_empty() {
        return input.prompt_template.clone();
    }
    let prompt = input
        .prompt_template
        .clone()
        .unwrap_or_else(|| crate::runtime::DEFAULT_TRIAGE_PROMPT.to_string());
    Some(append_triage_prompt_notes(prompt, &notes))
}

fn triage_prompt_notes(input: &TriageRunInput, finding: &Finding) -> Vec<String> {
    let grounding = crate::findings::grounding_prompt_note(finding)
        .map(|note| format!("Grounding note: {note}"));
    let feedback = suppression_feedback::feedback_note_for(&input.suppression_feedback, finding)
        .map(str::to_string);
    let prior = reviewed_refutation_prompt_note(input, finding);
    let source = source_evidence::model_note(input, finding);
    [grounding, feedback, prior, source]
        .into_iter()
        .flatten()
        .collect()
}

fn append_triage_prompt_notes(mut prompt: String, notes: &[String]) -> String {
    for note in notes {
        prompt.push_str(&format!("\n\n{note}"));
    }
    prompt
}

pub(in crate::modules) fn reviewed_refutation_prompt_note(
    input: &TriageRunInput,
    finding: &Finding,
) -> Option<String> {
    input
        .reviewed_refutation_priors
        .get(&finding.fingerprint)
        .map(crate::findings::ReviewedRefutationPrior::prompt_note)
}

pub(in crate::modules) fn persist_triage_outcome(
    store: &FindingStore,
    stats: &mut TriageRunStats,
    finding: Finding,
    runtime_outcome: TriageRuntimeOutcome,
    reconcile: IdentityReconcilePolicy,
) -> Result<()> {
    let TriageRuntimeOutcome {
        outcome,
        cached,
        failed_vote_summaries: _,
        evidence,
    } = runtime_outcome;
    let Some(finding_id) = finding.id else {
        stats.record_unpersisted_outcome(finding, outcome)?;
        return Ok(());
    };
    match record_triage_for_policy(store, &finding, &outcome, reconcile) {
        Ok(updated) if updated > 0 => {
            crate::capabilities::deep_auditor::record_evidence(store, finding_id, &evidence)?;
            if cached {
                stats.record_cached_outcome(finding, outcome)?;
            } else {
                stats.record_persisted_outcome(finding, outcome)?;
            }
        }
        Ok(_) => stats.record_policy_kept_outcome(finding, outcome, cached)?,
        Err(error) => {
            record_triage_persistence_diagnostic(&finding, &error);
            stats.record_persistence_error(&finding, &outcome, cached)?;
        }
    }
    Ok(())
}

fn record_triage_persistence_diagnostic(finding: &Finding, error: &anyhow::Error) {
    crate::runtime_diagnostics::record_runtime_diagnostic(
        "triage:run",
        format!(
            "could not persist triage for finding {}: {error}",
            finding.fingerprint
        ),
    );
}

/// A cluster duplicate inherits the representative's verdict without an LLM
/// call: persisted like an auto-triage, recorded with a `dedupe` stage row so
/// the operator can see the inheritance instead of a silent drop.
pub(in crate::modules) fn propagate_duplicate_outcome(
    store: &FindingStore,
    stats: &mut TriageRunStats,
    finding: Finding,
    representative_outcome: &TriageOutcome,
    representative_fingerprint: &str,
    reconcile: IdentityReconcilePolicy,
) {
    let inherited = TriageOutcome {
        rationale: duplicate_rationale(
            representative_fingerprint,
            &representative_outcome.rationale,
        ),
        cost_usd: 0.0,
        cost_usd_exact: true,
        ..representative_outcome.clone()
    };
    match record_triage_for_policy(store, &finding, &inherited, reconcile) {
        Ok(updated) if updated > 0 => {
            stats.record_duplicate_outcome(finding, inherited, representative_fingerprint, true);
        }
        Ok(_) => {
            stats.record_duplicate_outcome(finding, inherited, representative_fingerprint, false);
        }
        Err(error) => {
            record_triage_persistence_diagnostic(&finding, &error);
            stats.record_duplicate_persistence_error(&finding, representative_fingerprint);
        }
    }
}

fn record_triage_for_policy(
    store: &FindingStore,
    finding: &Finding,
    outcome: &TriageOutcome,
    reconcile: IdentityReconcilePolicy,
) -> Result<usize> {
    let finding_id = finding
        .id
        .context("persisted triage finding is missing its id")?;
    match reconcile {
        IdentityReconcilePolicy::Auto => store.record_auto_triage_for_identity(finding_id, outcome),
        IdentityReconcilePolicy::Off => store
            .record_auto_triage_locally(finding_id, outcome)
            .map(usize::from),
    }
}

pub(in crate::modules) fn high_confidence_false_positive(result: &Value) -> bool {
    result.get("verdict").and_then(Value::as_str) == Some("false_positive")
        && result.get("decisionApplied").and_then(Value::as_bool) != Some(false)
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
    let summary = format!(
        "{}\n      Selected Review model: {}",
        triage_summary(stage1, stats, &missing_fingerprints),
        config.stage2_model
    );
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
    let mut result = triage_response_envelope(&summary, data, &warnings, stats.result_status());
    add_triage_response_metadata(&mut result, warnings, stats.cost_report());
    result
}

fn triage_response_envelope(
    summary: &str,
    data: Value,
    warnings: &[String],
    status: crate::module_result::ToolResultStatus,
) -> Value {
    match status {
        crate::module_result::ToolResultStatus::Completed => {
            crate::module_result::completed_output_result(summary, summary, data)
        }
        crate::module_result::ToolResultStatus::Partial => {
            crate::module_result::partial_output_result(
                summary,
                summary,
                warnings.iter().map(|warning| json!(warning)).collect(),
                data,
            )
        }
        crate::module_result::ToolResultStatus::Failed => {
            crate::module_result::failed_output_result(summary, summary, data)
        }
        crate::module_result::ToolResultStatus::Skipped => unreachable!("triage stats cannot skip"),
    }
}

fn add_triage_response_metadata(
    result: &mut Value,
    warnings: Vec<String>,
    cost: crate::runtime::RuntimeCostReport,
) {
    if let Some(object) = result.as_object_mut() {
        object.insert("warnings".to_string(), json!(warnings));
    }
    crate::module_result::apply_runtime_cost_report(result, cost);
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
    let mut data = json!({
        "summary": summary,
        "triaged": stats.triaged(),
        "attempted": stats.attempted,
        "successful": stats.successful,
        "failed": stats.failed,
        "voteFailures": stats.vote_failures,
        "persistenceFailures": stats.persistence_failures,
        "unappliedOpinions": stats.unapplied_opinions,
        "errorSummaries": stats.error_summaries,
        "failures": stats.failure_details,
        "failureDetailsOmitted": stats.failure_details_omitted,
        "total": stage1.total,
        "tp": stats.tp,
        "fp": stats.fp,
        "needsReview": stats.needs_review,
        "byDesign": stats.by_design,
        "missingFingerprints": missing_fingerprints,
        "concurrency": input.concurrency,
        "votes": input.votes,
        "stage2Tier": triage_tier_label(input.stage2_tier),
        "highConfidenceFalsePositivesDropped": dropped_high_conf_fp,
        "stages": triage_stages(input, config, stage1, stats, dropped_high_conf_fp),
        "results": stats.results,
        "findings": stats.results,
    });
    apply_triage_budget_fields(&mut data, input, stats);
    crate::module_result::apply_runtime_cost_report(&mut data, stats.cost_report());
    data
}

/// The run's budget facts, kept together so the cap, what it left pending, and
/// whether it was the sole cause of an incomplete run cannot drift apart.
fn apply_triage_budget_fields(data: &mut Value, input: &TriageRunInput, stats: &TriageRunStats) {
    let Some(object) = data.as_object_mut() else {
        return;
    };
    object.insert("costCapUsd".to_string(), json!(input.cost_cap_usd));
    object.insert("costCapHit".to_string(), json!(stats.cost_cap_hit));
    object.insert(
        "pendingAfterCap".to_string(),
        json!(stats.pending_after_cap),
    );
    object.insert(
        "stoppedAtBudget".to_string(),
        json!(stats.stopped_at_budget()),
    );
}

fn triage_warnings(stats: &TriageRunStats, missing_fingerprints: &[String]) -> Vec<String> {
    let mut warnings = triage_failure_warnings(stats);
    warnings.extend(unapplied_opinion_notice(stats.unapplied_opinions));
    if stats.cost_cap_hit {
        warnings.push(cost_cap_warning(stats));
    }
    if let Some(warning) = unresolved_spend_warning(stats.cost_report()) {
        warnings.push(warning);
    }
    if !missing_fingerprints.is_empty() {
        warnings.push(format!(
            "{} requested finding(s) were not found.",
            missing_fingerprints.len()
        ));
    }
    warnings
}

fn unresolved_spend_warning(cost: crate::runtime::RuntimeCostReport) -> Option<String> {
    if cost.is_complete() {
        return None;
    }
    Some(match cost.estimated_total_usd() {
        Some(estimate) => format!(
            "Provider cost is unavailable; spend is estimated at ~${estimate:.4} from token usage and list prices."
        ),
        None => unresolved_spend_description(cost.observed_usd()),
    })
}

fn unresolved_spend_description(observed: f64) -> String {
    if observed == 0.0 {
        return "Provider cost is unknown; no charge has been recorded.".to_string();
    }
    format!("Provider spend is unresolved; observed subtotal is ${observed:.4}.")
}

pub(in crate::modules) fn unapplied_opinion_notice(count: usize) -> Option<String> {
    (count > 0).then(|| format!("{count} model opinion(s) retained without applying a review decision. Existing decisions remain authoritative."))
}

fn triage_failure_warnings(stats: &TriageRunStats) -> Vec<String> {
    if stats.failed == 0 && stats.vote_failures == 0 && stats.persistence_failures == 0 {
        return Vec::new();
    }
    let mut warnings = vec![triage_failure_warning(stats)];
    warnings.extend(stats.error_summaries.iter().cloned());
    if stats.failure_details_omitted > 0 {
        warnings.push(format!(
            "{} additional per-finding failure detail(s) were omitted from the bounded response.",
            stats.failure_details_omitted
        ));
    }
    warnings
}

fn triage_failure_warning(stats: &TriageRunStats) -> String {
    let preservation = if stats.successful > 0 {
        " Successful classifications were preserved where storage policy allowed."
    } else {
        " No classification completed successfully."
    };
    format!(
        "Triage degraded: failed classifications={}, failed consensus votes={}, failed persistence writes={}.{}",
        stats.failed, stats.vote_failures, stats.persistence_failures, preservation
    )
}

fn cost_cap_warning(stats: &TriageRunStats) -> String {
    if stats.cost_report().estimated_total_usd().is_some() {
        return format!(
            "Cost cap hit; {} finding(s) remain unevaluated.",
            stats.pending_after_cap
        );
    }
    format!(
        "Cost-cap enforcement halted on unresolved provider spend; {} finding(s) remain unevaluated.",
        stats.pending_after_cap
    )
}

pub(in crate::modules) fn triage_stages(
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    stage1: &PrefilteredTriageFindings,
    stats: &TriageRunStats,
    dropped_high_conf_fp: usize,
) -> Value {
    Value::Array(vec![
        json!({
            "stage": "prefilter",
            "kept": stage1.kept_count,
            "dropped": stage1.dropped,
            "rule": format!("prefilter_score >= {}", input.prefilter_threshold),
        }),
        json!({
            "stage": "dedupe",
            "clusters": stats.clusters,
            "duplicatesInherited": stats.duplicates_inherited,
            "rule": format!(
                "same tool+rule within {} lines inherits the representative verdict",
                crate::findings::ingest_contract::CLUSTER_WINDOW_LINES
            ),
        }),
        triage_model_stage(input, config, stats, dropped_high_conf_fp),
    ])
}

fn triage_model_stage(
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    stats: &TriageRunStats,
    dropped_high_conf_fp: usize,
) -> Value {
    let mut stage = json!({
        "stage": "haiku",
        "stageKind": "model-review",
        "stageLabel": "Model review",
        "model": config.stage2_model,
        "concurrency": input.concurrency,
        "votes": input.votes,
        "triaged": stats.triaged(),
        "attempted": stats.attempted,
        "successful": stats.successful,
        "failed": stats.failed,
        "voteFailures": stats.vote_failures,
        "persistenceFailures": stats.persistence_failures,
        "errorSummaries": stats.error_summaries,
        "failureDetailsOmitted": stats.failure_details_omitted,
        "tp": stats.tp,
        "fp": stats.fp,
        "needsReview": stats.needs_review,
        "byDesign": stats.by_design,
        "highConfidenceFalsePositivesDropped": dropped_high_conf_fp,
        "costCapHit": stats.cost_cap_hit,
        "pendingAfterCap": stats.pending_after_cap,
    });
    crate::module_result::apply_runtime_cost_report(&mut stage, stats.cost_report());
    stage
}
