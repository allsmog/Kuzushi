use super::*;

pub(in crate::modules) struct TriageRunStats {
    pub(in crate::modules) tp: usize,
    pub(in crate::modules) fp: usize,
    pub(in crate::modules) needs_review: usize,
    pub(in crate::modules) by_design: usize,
    cost: crate::runtime::RuntimeCostReport,
    pub(in crate::modules) cost_cap_hit: bool,
    pub(in crate::modules) pending_after_cap: usize,
    pub(in crate::modules) results: Vec<Value>,
}

impl Default for TriageRunStats {
    fn default() -> Self {
        Self {
            tp: 0,
            fp: 0,
            needs_review: 0,
            by_design: 0,
            cost: crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO),
            cost_cap_hit: false,
            pending_after_cap: 0,
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
        finding: Finding,
        error: anyhow::Error,
    ) {
        self.cost = self.cost.mark_incomplete();
        self.needs_review += 1;
        let mut result = json!({
            "fingerprint": finding.fingerprint,
            "stage": "haiku",
            "verdict": "needs_review",
            "confidence": 0.0,
            "rationale": format!("triage call failed: {error}"),
        });
        crate::module_result::apply_runtime_cost_report(
            &mut result,
            crate::runtime::RuntimeCostReport::INCOMPLETE_ZERO,
        );
        self.results.push(result);
    }

    pub(in crate::modules) fn record_unpersisted_outcome(
        &mut self,
        finding: Finding,
        outcome: TriageOutcome,
    ) -> Result<()> {
        let cost = crate::runtime::triage_cost_report(&outcome)?;
        self.record_provider_cost(cost)?;
        self.record_verdict(outcome.verdict);
        let mut result = json!({
            "fingerprint": finding.fingerprint,
            "stage": "haiku",
            "verdict": outcome.verdict.as_str(),
            "confidence": outcome.confidence,
            "rationale": "finding lacked SQLite id; verdict not persisted",
        });
        crate::module_result::apply_runtime_cost_report(&mut result, cost);
        self.results.push(result);
        Ok(())
    }

    pub(in crate::modules) fn record_persisted_outcome(
        &mut self,
        finding: Finding,
        outcome: TriageOutcome,
    ) -> Result<()> {
        let cost = crate::runtime::triage_cost_report(&outcome)?;
        self.record_provider_cost(cost)?;
        self.record_verdict(outcome.verdict);
        let mut result = json!({
            "fingerprint": finding.fingerprint,
            "stage": "haiku",
            "verdict": outcome.verdict.as_str(),
            "confidence": outcome.confidence,
            "rationale": outcome.rationale,
        });
        crate::module_result::apply_runtime_cost_report(&mut result, cost);
        self.results.push(result);
        Ok(())
    }

    pub(in crate::modules) fn record_cached_outcome(
        &mut self,
        finding: Finding,
        outcome: TriageOutcome,
    ) {
        self.record_verdict(outcome.verdict);
        let mut result = json!({
            "fingerprint": finding.fingerprint,
            "stage": "haiku",
            "verdict": outcome.verdict.as_str(),
            "confidence": outcome.confidence,
            "rationale": outcome.rationale,
            "cached": true,
        });
        crate::module_result::apply_runtime_cost_report(
            &mut result,
            crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO),
        );
        self.results.push(result);
    }

    fn record_provider_cost(&mut self, cost: crate::runtime::RuntimeCostReport) -> Result<()> {
        self.cost = self.cost.checked_add(cost, "triage accumulated cost")?;
        Ok(())
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

pub(in crate::modules) fn run_triage_stage2(
    store: &FindingStore,
    runtime: &dyn AgentRuntime,
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    findings: Vec<Finding>,
) -> Result<TriageRunStats> {
    let mut stats = TriageRunStats::with_capacity(findings.len());
    for finding in findings {
        triage_one_finding(store, runtime, input, config, &mut stats, finding)?;
    }
    Ok(stats)
}

pub(in crate::modules) fn triage_one_finding(
    store: &FindingStore,
    runtime: &dyn AgentRuntime,
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    stats: &mut TriageRunStats,
    finding: Finding,
) -> Result<()> {
    if triage_cost_cap_reached(input.cost_cap_usd, stats.cost_report()) {
        stats.record_cost_cap_pending();
        return Ok(());
    }

    let runtime_outcome = match collect_triage_votes(runtime, config, input, &finding) {
        Ok(runtime_outcome) => runtime_outcome,
        Err(error) if is_cancelled_runtime_error(&error) => {
            return Err(error).context("triage:run cancelled");
        }
        Err(error) => {
            stats.record_runtime_error(finding, error);
            return Ok(());
        }
    };
    persist_triage_outcome(store, stats, finding, runtime_outcome)?;
    Ok(())
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
    let mut votes = vec![first.outcome];
    let mut failed = 0usize;
    for _ in 1..input.votes {
        match call_triage_runtime_uncached(runtime, config, input, finding) {
            Ok(outcome) => votes.push(outcome),
            Err(error) if is_cancelled_runtime_error(&error) => return Err(error),
            Err(_) => failed += 1,
        }
    }
    let mut outcome = consensus_outcome(votes);
    if failed > 0 {
        outcome.cost_usd_exact = false;
        outcome.rationale = format!("{} ({failed} vote call(s) failed)", outcome.rationale);
    }
    Ok(TriageRuntimeOutcome {
        outcome,
        cached: false,
    })
}

fn is_cancelled_runtime_error(error: &anyhow::Error) -> bool {
    let message = format!("{error:#}").to_ascii_lowercase();
    message.contains("cancelled") || message.contains("canceled")
}
