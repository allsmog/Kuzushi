use super::*;

#[derive(Default)]
pub(in crate::modules) struct TriageRunStats {
    pub(in crate::modules) tp: usize,
    pub(in crate::modules) fp: usize,
    pub(in crate::modules) needs_review: usize,
    pub(in crate::modules) by_design: usize,
    pub(in crate::modules) total_cost: f64,
    pub(in crate::modules) cost_cap_hit: bool,
    pub(in crate::modules) pending_after_cap: usize,
    pub(in crate::modules) results: Vec<Value>,
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
        self.needs_review += 1;
        self.results.push(json!({
            "fingerprint": finding.fingerprint,
            "stage": "haiku",
            "verdict": "needs_review",
            "confidence": 0.0,
            "rationale": format!("triage call failed: {error}"),
        }));
    }

    pub(in crate::modules) fn record_unpersisted_outcome(
        &mut self,
        finding: Finding,
        outcome: TriageOutcome,
    ) {
        self.results.push(json!({
            "fingerprint": finding.fingerprint,
            "stage": "haiku",
            "verdict": outcome.verdict.as_str(),
            "confidence": outcome.confidence,
            "rationale": "finding lacked SQLite id; verdict not persisted",
        }));
    }

    pub(in crate::modules) fn record_persisted_outcome(
        &mut self,
        finding: Finding,
        outcome: TriageOutcome,
    ) {
        self.total_cost += outcome.cost_usd;
        self.record_verdict(outcome.verdict);
        self.results.push(json!({
            "fingerprint": finding.fingerprint,
            "stage": "haiku",
            "verdict": outcome.verdict.as_str(),
            "confidence": outcome.confidence,
            "rationale": outcome.rationale,
            "costUsd": outcome.cost_usd,
        }));
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
        triage_one_finding(store, runtime, input, config, &mut stats, finding);
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
) {
    if triage_cost_cap_reached(input.cost_cap_usd, stats.total_cost) {
        stats.record_cost_cap_pending();
        return;
    }

    let outcome = match call_triage_runtime(runtime, config, input, &finding) {
        Ok(outcome) => outcome,
        Err(error) => {
            stats.record_runtime_error(finding, error);
            return;
        }
    };
    persist_triage_outcome(store, stats, finding, outcome);
}
