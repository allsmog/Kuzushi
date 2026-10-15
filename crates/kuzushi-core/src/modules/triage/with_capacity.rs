use super::*;

const MAX_TRIAGE_ERROR_SUMMARIES: usize = 8;
const MAX_TRIAGE_FAILURE_DETAILS: usize = 32;

pub(in crate::modules) struct TriageRunStats {
    pub(in crate::modules) tp: usize,
    pub(in crate::modules) fp: usize,
    pub(in crate::modules) needs_review: usize,
    pub(in crate::modules) by_design: usize,
    pub(in crate::modules) attempted: usize,
    pub(in crate::modules) successful: usize,
    pub(in crate::modules) failed: usize,
    pub(in crate::modules) vote_failures: usize,
    pub(in crate::modules) persistence_failures: usize,
    pub(in crate::modules) unapplied_opinions: usize,
    pub(in crate::modules) error_summaries: Vec<String>,
    pub(in crate::modules) failure_details: Vec<Value>,
    pub(in crate::modules) failure_details_omitted: usize,
    cost: crate::runtime::RuntimeCostReport,
    pub(in crate::modules) cost_cap_hit: bool,
    pub(in crate::modules) pending_after_cap: usize,
    pub(in crate::modules) clusters: usize,
    pub(in crate::modules) duplicates_inherited: usize,
    pub(in crate::modules) results: Vec<Value>,
}

impl Default for TriageRunStats {
    fn default() -> Self {
        Self {
            tp: 0,
            fp: 0,
            needs_review: 0,
            by_design: 0,
            attempted: 0,
            successful: 0,
            failed: 0,
            vote_failures: 0,
            persistence_failures: 0,
            unapplied_opinions: 0,
            error_summaries: Vec::new(),
            failure_details: Vec::new(),
            failure_details_omitted: 0,
            cost: crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO),
            cost_cap_hit: false,
            pending_after_cap: 0,
            clusters: 0,
            duplicates_inherited: 0,
            results: Vec::new(),
        }
    }
}

impl TriageRunStats {
    pub(in crate::modules) fn with_capacity(capacity: usize) -> Self {
        Self {
            results: Vec::with_capacity(capacity),
            ..Self::default()
        }
    }

    pub(in crate::modules) fn triaged(&self) -> usize {
        self.results.len()
    }

    pub(in crate::modules) fn cost_report(&self) -> crate::runtime::RuntimeCostReport {
        self.cost
    }

    /// `Completed` means every selected finding was evaluated. A cost cap that
    /// defers findings leaves real work undone, so it downgrades the run to
    /// `Partial` even when nothing failed — otherwise scan-stage receipts, the
    /// `kuzushi run` envelope, and the shell's partial-attempt acknowledgement
    /// would read a truncated triage as full coverage.
    pub(in crate::modules) fn result_status(&self) -> crate::module_result::ToolResultStatus {
        if self.degraded() {
            return if self.successful == 0 {
                crate::module_result::ToolResultStatus::Failed
            } else {
                crate::module_result::ToolResultStatus::Partial
            };
        }
        if self.pending_after_cap > 0 {
            return crate::module_result::ToolResultStatus::Partial;
        }
        crate::module_result::ToolResultStatus::Completed
    }

    fn degraded(&self) -> bool {
        self.failed > 0 || self.vote_failures > 0 || self.persistence_failures > 0
    }

    /// True when the configured cost cap is the *only* reason this run is
    /// incomplete. A consumer may keep the partial output and continue; a
    /// partial caused by any failure has no such guarantee.
    pub(in crate::modules) fn stopped_at_budget(&self) -> bool {
        self.pending_after_cap > 0 && !self.degraded()
    }

    pub(in crate::modules) fn high_confidence_false_positive_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| high_confidence_false_positive(result))
            .count()
    }

    pub(in crate::modules) fn record_cost_cap_pending(&mut self) {
        self.cost_cap_hit = true;
        self.pending_after_cap += 1;
    }

    pub(in crate::modules) fn record_runtime_error(
        &mut self,
        finding: &Finding,
        error: &anyhow::Error,
    ) {
        self.cost = self.cost.mark_incomplete();
        self.attempted += 1;
        self.failed += 1;
        let summary = safe_triage_runtime_error(error);
        self.record_error_summary(summary.clone());
        self.record_failure_detail(json!({
            "fingerprint": finding.fingerprint,
            "stage": "haiku",
            "stageKind": "model-review",
            "error": summary,
        }));
    }

    pub(in crate::modules) fn record_blocked_duplicate(
        &mut self,
        finding: &Finding,
        representative_fingerprint: &str,
    ) {
        self.record_failure_detail(json!({
            "fingerprint": finding.fingerprint,
            "stage": "dedupe",
            "error": "cluster representative classification failed",
            "blockedBy": representative_fingerprint,
        }));
    }

    pub(in crate::modules) fn record_vote_failures(
        &mut self,
        finding: &Finding,
        summaries: &[String],
    ) {
        if summaries.is_empty() {
            return;
        }
        self.cost = self.cost.mark_incomplete();
        self.vote_failures += summaries.len();
        for summary in summaries {
            self.record_error_summary(summary.clone());
        }
        self.record_failure_detail(json!({
            "fingerprint": finding.fingerprint,
            "stage": "consensus",
            "failedVotes": summaries.len(),
            "errors": summaries,
        }));
    }

    pub(in crate::modules) fn record_unpersisted_outcome(
        &mut self,
        finding: Finding,
        outcome: TriageOutcome,
    ) -> Result<()> {
        let cost = crate::runtime::triage_cost_report(&outcome)?;
        self.record_provider_cost(cost)?;
        self.record_verdict(outcome.verdict);
        self.record_successful_classification();
        self.persistence_failures += 1;
        self.record_error_summary("triage verdict was not persisted".to_string());
        self.record_failure_detail(json!({
            "fingerprint": finding.fingerprint,
            "stage": "verdict-write",
            "error": "finding lacked a durable store identity",
        }));
        let mut result = json!({
            "fingerprint": finding.fingerprint,
            "stage": "haiku",
            "stageKind": "model-review",
            "verdict": outcome.verdict.as_str(),
            "confidence": outcome.confidence,
            "rationale": "finding lacked SQLite id; verdict not persisted",
        });
        self.record_application_status(&mut result, false);
        crate::module_result::apply_runtime_cost_report(&mut result, cost);
        self.results.push(result);
        Ok(())
    }

    pub(in crate::modules) fn record_persisted_outcome(
        &mut self,
        finding: Finding,
        outcome: TriageOutcome,
    ) -> Result<()> {
        self.record_classified_outcome(finding, outcome, false, true)
    }

    pub(in crate::modules) fn record_policy_kept_outcome(
        &mut self,
        finding: Finding,
        outcome: TriageOutcome,
        cached: bool,
    ) -> Result<()> {
        self.record_classified_outcome(finding, outcome, cached, false)
    }

    fn record_classified_outcome(
        &mut self,
        finding: Finding,
        outcome: TriageOutcome,
        cached: bool,
        decision_applied: bool,
    ) -> Result<()> {
        let cost = if cached {
            crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO)
        } else {
            crate::runtime::triage_cost_report(&outcome)?
        };
        self.record_provider_cost(cost)?;
        self.record_verdict(outcome.verdict);
        self.record_successful_classification();
        let mut result = json!({
            "fingerprint": finding.fingerprint,
            "stage": if decision_applied { "haiku" } else { "model-opinion" },
            "stageKind": "model-review",
            "verdict": outcome.verdict.as_str(),
            "confidence": outcome.confidence,
            "rationale": outcome.rationale,
            "cached": cached,
        });
        self.record_application_status(&mut result, decision_applied);
        crate::module_result::apply_runtime_cost_report(&mut result, cost);
        self.results.push(result);
        Ok(())
    }

    pub(in crate::modules) fn record_duplicate_outcome(
        &mut self,
        finding: Finding,
        outcome: TriageOutcome,
        representative_fingerprint: &str,
        decision_applied: bool,
    ) {
        self.duplicates_inherited += usize::from(decision_applied);
        self.record_verdict(outcome.verdict);
        let mut result = json!({
            "fingerprint": finding.fingerprint,
            "stage": "dedupe",
            "verdict": outcome.verdict.as_str(),
            "confidence": outcome.confidence,
            "rationale": outcome.rationale,
            "duplicateOf": representative_fingerprint,
        });
        self.record_application_status(&mut result, decision_applied);
        crate::module_result::apply_runtime_cost_report(
            &mut result,
            crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO),
        );
        self.results.push(result);
    }

    pub(in crate::modules) fn record_persistence_error(
        &mut self,
        finding: &Finding,
        outcome: &TriageOutcome,
        cached: bool,
    ) -> Result<()> {
        let cost = if cached {
            crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO)
        } else {
            crate::runtime::triage_cost_report(outcome)?
        };
        self.record_provider_cost(cost)?;
        self.attempted += 1;
        self.failed += 1;
        self.persistence_failures += 1;
        self.record_error_summary("triage verdict persistence failed".to_string());
        self.record_failure_detail(json!({
            "fingerprint": finding.fingerprint,
            "stage": "verdict-write",
            "error": "triage verdict persistence failed",
        }));
        Ok(())
    }

    pub(in crate::modules) fn record_duplicate_persistence_error(
        &mut self,
        finding: &Finding,
        representative_fingerprint: &str,
    ) {
        self.persistence_failures += 1;
        self.record_error_summary("inherited triage verdict persistence failed".to_string());
        self.record_failure_detail(json!({
            "fingerprint": finding.fingerprint,
            "stage": "dedupe-write",
            "error": "inherited triage verdict persistence failed",
            "duplicateOf": representative_fingerprint,
        }));
    }

    pub(in crate::modules) fn record_cached_outcome(
        &mut self,
        finding: Finding,
        outcome: TriageOutcome,
    ) -> Result<()> {
        self.record_classified_outcome(finding, outcome, true, true)
    }

    fn record_application_status(&mut self, result: &mut Value, decision_applied: bool) {
        self.unapplied_opinions += usize::from(!decision_applied);
        result["decisionApplied"] = json!(decision_applied);
        result["applicationStatus"] = json!(if decision_applied {
            "applied"
        } else {
            "not_applied"
        });
    }

    fn record_provider_cost(&mut self, cost: crate::runtime::RuntimeCostReport) -> Result<()> {
        self.cost = self.cost.checked_add(cost, "triage accumulated cost")?;
        Ok(())
    }

    fn record_successful_classification(&mut self) {
        self.attempted += 1;
        self.successful += 1;
    }

    fn record_error_summary(&mut self, summary: String) {
        if self.error_summaries.len() < MAX_TRIAGE_ERROR_SUMMARIES
            && !self.error_summaries.contains(&summary)
        {
            self.error_summaries.push(summary);
        }
    }

    fn record_failure_detail(&mut self, detail: Value) {
        if self.failure_details.len() < MAX_TRIAGE_FAILURE_DETAILS {
            self.failure_details.push(detail);
        } else {
            self.failure_details_omitted += 1;
        }
    }

    pub(in crate::modules) fn record_verdict(&mut self, verdict: TriageVerdict) {
        match verdict {
            TriageVerdict::TruePositive => self.tp += 1,
            TriageVerdict::FalsePositive => self.fp += 1,
            TriageVerdict::NeedsReview => self.needs_review += 1,
            TriageVerdict::ByDesign => self.by_design += 1,
        }
    }
}

fn safe_triage_runtime_error(error: &anyhow::Error) -> String {
    if let Some(metadata) = crate::runtime::runtime_failure_metadata(error) {
        return format!("model request failed ({})", metadata.error_class);
    }
    crate::runtime::safe_model_failure_message(&format!("{error:#}"))
}

pub(in crate::modules) fn run_triage_stage2(
    store: &FindingStore,
    runtime: &dyn AgentRuntime,
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    findings: Vec<Finding>,
) -> Result<TriageRunStats> {
    run_triage_stage2_with(store, input, findings, &|finding| {
        collect_triage_votes(runtime, config, input, finding)
    })
}

/// Deep bulk classification: every cluster representative goes through the
/// code-reading deep auditor instead of the single-shot evidence-only call.
/// Cost cap, clustering, and duplicate propagation are identical to the
/// standard path; `votes` maps onto deep-auditor consensus passes.
pub(in crate::modules) fn run_triage_stage2_deep(
    store: &FindingStore,
    routed: &crate::agent_router::RoutedRuntime<'_>,
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    findings: Vec<Finding>,
    trace: Option<&crate::run_artifacts::TraceHandle>,
) -> Result<TriageRunStats> {
    run_triage_stage2_with(store, input, findings, &|finding| {
        deep_triage_outcome(routed, config, input, finding, trace)
    })
}

fn run_triage_stage2_with(
    store: &FindingStore,
    input: &TriageRunInput,
    findings: Vec<Finding>,
    classify: &dyn Fn(&Finding) -> Result<TriageRuntimeOutcome>,
) -> Result<TriageRunStats> {
    let mut clusters = cluster_triage_findings(findings);
    order_clusters_by_reviewed_refutation(&mut clusters, input);
    let mut stats = TriageRunStats::with_capacity(clusters.len());
    stats.clusters = clusters.len();
    for cluster in clusters {
        triage_one_cluster(store, input, &mut stats, cluster, classify)?;
    }
    Ok(stats)
}

fn order_clusters_by_reviewed_refutation(clusters: &mut [TriageCluster], input: &TriageRunInput) {
    // Higher historical refutation signal is reviewed first to accelerate
    // false-positive reduction. Stable sorting preserves the prior order for
    // equal/missing signals, and every cluster remains in the slice.
    clusters.sort_by(|left, right| {
        let left = reviewed_refutation_rate(input, &left.representative);
        let right = reviewed_refutation_rate(input, &right.representative);
        match (left, right) {
            (Some(left), Some(right)) => right.total_cmp(&left),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });
}

fn reviewed_refutation_rate(input: &TriageRunInput, finding: &Finding) -> Option<f64> {
    input
        .reviewed_refutation_priors
        .get(&finding.fingerprint)
        .map(|prior| prior.shrunken_refutation_rate)
}

fn deep_triage_outcome(
    routed: &crate::agent_router::RoutedRuntime<'_>,
    config: &TriageExecutionConfig,
    input: &TriageRunInput,
    finding: &Finding,
    trace: Option<&crate::run_artifacts::TraceHandle>,
) -> Result<TriageRuntimeOutcome> {
    let cfg = deep_triage_config(config, input, finding);
    let outcome = crate::capabilities::deep_auditor::run_deep_auditor_traced(
        routed, None, &cfg, finding, trace,
    )?;
    Ok(TriageRuntimeOutcome {
        outcome: outcome.triage,
        cached: false,
        failed_vote_summaries: Vec::new(),
        evidence: outcome.evidence,
    })
}

fn deep_triage_config(
    config: &TriageExecutionConfig,
    input: &TriageRunInput,
    finding: &Finding,
) -> crate::capabilities::deep_auditor::DeepAuditConfig {
    let base = crate::capabilities::deep_auditor::DeepAuditConfig::new(config.cwd.clone());
    let tuning = input.deep_tuning;
    crate::capabilities::deep_auditor::DeepAuditConfig {
        passes: input.votes as u32,
        max_steps: tuning.max_steps.unwrap_or(base.max_steps),
        deposit_usd: tuning.deposit_usd.unwrap_or(base.deposit_usd),
        temperature: tuning.temperature.unwrap_or(base.temperature),
        taint_tools: tuning.taint_tools,
        reviewed_refutation_context: reviewed_refutation_prompt_note(input, finding),
        threat_model_context: input.threat_model_context.clone(),
        ..base
    }
}

#[cfg(test)]
mod reviewed_refutation_prior_tests {
    use super::*;
    use crate::findings::{RefutationCohortKey, ReviewedRefutationPrior};

    #[test]
    fn deep_triage_carries_the_selected_context_into_every_audit_pass() {
        let root = tempfile::tempdir().unwrap();
        let first =
            crate::capabilities::threat_model::commit_test_model(root.path(), "ACCEPTED_ALPHA");
        crate::capabilities::threat_model::commit_test_model(root.path(), "ACTIVE_BETA");
        let raw = json!({"threatModelRef": first, "votes": 3});
        let mut input = TriageRunInput::from_tool_input(&raw, root.path()).unwrap();
        apply_threat_model_triage_context(&mut input, root.path(), &raw).unwrap();
        let execution =
            TriageExecutionConfig::new(root.path().to_path_buf(), "openai:gpt-5.5".to_string());
        let config = deep_triage_config(&execution, &input, &finding("candidate", "fixture"));
        assert_eq!(config.passes, 3);
        let digest = config.threat_model_context.unwrap();
        assert!(digest.contains("ACCEPTED_ALPHA"));
        assert!(!digest.contains("ACTIVE_BETA"));
    }

    fn finding(fingerprint: &str, rule: &str) -> Finding {
        let mut finding = Finding::new_tool(
            "semgrep",
            rule,
            format!("src/{fingerprint}.rs"),
            10,
            Some(10),
            Severity::High,
            "candidate",
        );
        finding.fingerprint = fingerprint.to_string();
        finding
    }

    fn prior(rule: &str, rate: f64) -> ReviewedRefutationPrior {
        ReviewedRefutationPrior {
            key: RefutationCohortKey {
                tool: "semgrep".to_string(),
                rule_id: rule.to_string(),
                rule_version: Some("1".to_string()),
                tool_version: None,
                rule_set_hash: None,
                config_hash: None,
                language: Some("rust".to_string()),
            },
            emitted: 10,
            reviewed: 4,
            refuted: 3,
            shrunken_refutation_rate: rate,
            credible_interval_90: [0.3, 0.9],
        }
    }

    #[test]
    fn advisory_prior_stably_orders_without_removing_clusters() {
        let mut input = TriageRunInput::from_tool_input(&json!({}), Path::new(".")).unwrap();
        input
            .reviewed_refutation_priors
            .insert("high".to_string(), prior("high-rule", 0.8));
        input
            .reviewed_refutation_priors
            .insert("low".to_string(), prior("low-rule", 0.2));
        let mut clusters = cluster_triage_findings(vec![
            finding("none", "none-rule"),
            finding("low", "low-rule"),
            finding("high", "high-rule"),
        ]);

        order_clusters_by_reviewed_refutation(&mut clusters, &input);

        assert_eq!(clusters.len(), 3);
        assert_eq!(clusters[0].representative.fingerprint, "high");
        assert_eq!(clusters[1].representative.fingerprint, "low");
        assert_eq!(clusters[2].representative.fingerprint, "none");
    }

    #[test]
    fn deep_config_receives_the_same_advisory_prompt_context() {
        let finding = finding("candidate", "CWE-89");
        let mut input = TriageRunInput::from_tool_input(&json!({}), Path::new(".")).unwrap();
        input
            .reviewed_refutation_priors
            .insert(finding.fingerprint.clone(), prior("CWE-89", 0.8));
        let config = TriageExecutionConfig::new(PathBuf::from("."), "provider:model".to_string());

        let cfg = deep_triage_config(&config, &input, &finding);

        let context = cfg.reviewed_refutation_context.unwrap();
        assert!(
            context.contains("human-reviewed refutation prior"),
            "{context}"
        );
        assert!(context.contains("never suppress or decide"), "{context}");
        assert!(context.contains("3/4 reviewed refuted"), "{context}");
        assert!(context.contains("4/10 emitted reviewed"), "{context}");
    }
}

fn triage_one_cluster(
    store: &FindingStore,
    input: &TriageRunInput,
    stats: &mut TriageRunStats,
    cluster: TriageCluster,
    classify: &dyn Fn(&Finding) -> Result<TriageRuntimeOutcome>,
) -> Result<()> {
    if defer_cluster_for_cost_cap(input, stats, cluster.duplicates.len()) {
        return Ok(());
    }

    let Some(runtime_outcome) = classify_cluster_representative(
        stats,
        &cluster.representative,
        &cluster.duplicates,
        classify,
    )?
    else {
        return Ok(());
    };
    persist_cluster_outcomes(store, input, stats, cluster, runtime_outcome)
}

fn persist_cluster_outcomes(
    store: &FindingStore,
    input: &TriageRunInput,
    stats: &mut TriageRunStats,
    cluster: TriageCluster,
    runtime_outcome: TriageRuntimeOutcome,
) -> Result<()> {
    let representative = cluster.representative;
    stats.record_vote_failures(&representative, &runtime_outcome.failed_vote_summaries);
    let inherited = runtime_outcome.outcome.clone();
    let representative_fingerprint = representative.fingerprint.clone();
    persist_triage_outcome(
        store,
        stats,
        representative,
        runtime_outcome,
        input.identity_reconcile,
    )?;
    for duplicate in cluster.duplicates {
        propagate_duplicate_outcome(
            store,
            stats,
            duplicate,
            &inherited,
            &representative_fingerprint,
            input.identity_reconcile,
        );
    }
    Ok(())
}

fn defer_cluster_for_cost_cap(
    input: &TriageRunInput,
    stats: &mut TriageRunStats,
    duplicate_count: usize,
) -> bool {
    if !triage_cost_cap_reached(input.cost_cap_usd, stats.cost_report()) {
        return false;
    }
    for _ in 0..=duplicate_count {
        stats.record_cost_cap_pending();
    }
    true
}

fn classify_cluster_representative(
    stats: &mut TriageRunStats,
    representative: &Finding,
    duplicates: &[Finding],
    classify: &dyn Fn(&Finding) -> Result<TriageRuntimeOutcome>,
) -> Result<Option<TriageRuntimeOutcome>> {
    match classify(representative) {
        Ok(outcome) => Ok(Some(outcome)),
        Err(error) if is_cancelled_runtime_error(&error) => {
            Err(error).context("triage:run cancelled")
        }
        Err(error) => {
            stats.record_runtime_error(representative, &error);
            for duplicate in duplicates {
                stats.record_blocked_duplicate(duplicate, &representative.fingerprint);
            }
            Ok(None)
        }
    }
}

/// Vote #1 goes through the cache-aware path; extra votes are fresh,
/// uncached calls folded into one consensus outcome. A finding whose extra
/// votes all fail still resolves from the votes that succeeded, with the
/// failure count on record; only losing every vote surfaces as an error.
fn collect_triage_votes(
    runtime: &dyn AgentRuntime,
    config: &TriageExecutionConfig,
    input: &TriageRunInput,
    finding: &Finding,
) -> Result<TriageRuntimeOutcome> {
    let first = call_triage_runtime(runtime, config, input, finding)?;
    if input.votes <= 1 {
        return Ok(first);
    }
    let (votes, failed_vote_summaries) =
        collect_additional_votes(runtime, config, input, finding, first.outcome)?;
    let mut outcome = consensus_outcome(votes);
    if !failed_vote_summaries.is_empty() {
        // A failed vote may have spent without a receipt or an estimate.
        outcome.cost_usd_exact = false;
        outcome.estimated_cost_usd = None;
        outcome.rationale = format!(
            "{} ({} vote call(s) failed)",
            outcome.rationale,
            failed_vote_summaries.len()
        );
    }
    Ok(TriageRuntimeOutcome {
        outcome,
        cached: false,
        failed_vote_summaries,
        evidence: Vec::new(),
    })
}

fn collect_additional_votes(
    runtime: &dyn AgentRuntime,
    config: &TriageExecutionConfig,
    input: &TriageRunInput,
    finding: &Finding,
    first: TriageOutcome,
) -> Result<(Vec<TriageOutcome>, Vec<String>)> {
    let mut votes = vec![first];
    let mut failures = Vec::new();
    for _ in 1..input.votes {
        match call_triage_runtime_uncached(runtime, config, input, finding) {
            Ok(outcome) => votes.push(outcome),
            Err(error) if is_cancelled_runtime_error(&error) => return Err(error),
            Err(error) => failures.push(safe_triage_runtime_error(&error)),
        }
    }
    Ok((votes, failures))
}

fn is_cancelled_runtime_error(error: &anyhow::Error) -> bool {
    let message = format!("{error:#}").to_ascii_lowercase();
    message.contains("cancelled") || message.contains("canceled")
}
