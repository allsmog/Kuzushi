use super::{BatchOccurrenceRow, BatchTrialReport, IdentityFoldPolicy};
use crate::findings::{
    is_attack_chain_finding, Finding, FindingIdentityBasis, FindingStore, Severity,
    StaticProofState,
};
use anyhow::{Context, Result};
use std::path::Path;
mod observations;
use observations::load_observations;
use std::collections::{BTreeMap, BTreeSet};

pub fn finding_projection_key(finding: &Finding, policy: IdentityFoldPolicy) -> String {
    if is_attack_chain_finding(finding) {
        return format!("fingerprint:{}", finding.fingerprint);
    }
    match policy {
        IdentityFoldPolicy::Legacy => legacy_key(finding),
        IdentityFoldPolicy::Safe => safe_key(finding),
        IdentityFoldPolicy::Aggressive => aggressive_key(finding),
    }
}

fn legacy_key(finding: &Finding) -> String {
    finding
        .dedup_key
        .as_ref()
        .map(|key| format!("dedup:{key}"))
        .unwrap_or_else(|| format!("fingerprint:{}", finding.fingerprint))
}

fn aggressive_key(finding: &Finding) -> String {
    finding
        .identity_id
        .as_ref()
        .map(|key| format!("identity:{key}"))
        .unwrap_or_else(|| legacy_key(finding))
}

fn safe_key(finding: &Finding) -> String {
    let Some(identity_id) = finding.identity_id.as_deref() else {
        return legacy_key(finding);
    };
    if finding.effective_identity_basis().is_strong() {
        return format!("identity:{identity_id}");
    }
    fallback_identity_key(finding, identity_id)
}

fn fallback_identity_key(finding: &Finding, identity_id: &str) -> String {
    if let Some(signature) = nonempty_identity_evidence(finding.source_signature.as_deref()) {
        return format!("identity:{identity_id}:source:{signature}");
    }
    if let Some(dedup_key) = nonempty_identity_evidence(finding.dedup_key.as_deref()) {
        return format!("identity:{identity_id}:dedup:{dedup_key}");
    }
    format!("fingerprint:{}", finding.fingerprint)
}

fn nonempty_identity_evidence(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[derive(Clone, Copy)]
pub(super) struct LogicalTrialCounts {
    pub(super) planned: usize,
    pub(super) completed: usize,
    pub(super) failed: usize,
    pub(super) pending: usize,
}

impl LogicalTrialCounts {
    pub(super) fn from_trials(trials: &[BatchTrialReport]) -> Self {
        let completed = trials
            .iter()
            .filter(|trial| trial.state == "completed")
            .count();
        let failed = trials.iter().filter(|trial| trial_is_failed(trial)).count();
        Self {
            planned: trials.len(),
            completed,
            failed,
            pending: trials.len().saturating_sub(completed + failed),
        }
    }
}

fn trial_is_failed(trial: &BatchTrialReport) -> bool {
    trial.state == "failed" || (trial.state == "parked" && trial.attempts > 0)
}

pub(super) fn occurrence_rows(
    root: &Path,
    store: &FindingStore,
    trials: &[BatchTrialReport],
    policy: IdentityFoldPolicy,
    counts: LogicalTrialCounts,
) -> Result<Vec<BatchOccurrenceRow>> {
    let observations = load_observations(root, store, trials)?;
    let fold_context = OccurrenceFoldContext::load(&observations);
    let mut groups = BTreeMap::<String, OccurrenceAccumulator>::new();
    fold_retained_observations(&observations, policy, &fold_context, &mut groups);
    for trial in trials.iter().filter(|trial| trial.state == "completed") {
        fold_completed_trial(
            root,
            trial,
            &observations,
            policy,
            &fold_context,
            &mut groups,
        )?;
    }
    Ok(groups
        .into_iter()
        .map(|(key, group)| group.finish(key, counts))
        .collect())
}

fn fold_retained_observations(
    observations: &BTreeMap<String, Vec<Finding>>,
    policy: IdentityFoldPolicy,
    context: &OccurrenceFoldContext,
    groups: &mut BTreeMap<String, OccurrenceAccumulator>,
) {
    for (run, findings) in observations {
        for finding in findings {
            groups
                .entry(context.projection_key(finding, policy))
                .or_default()
                .observe_finding(run, finding);
        }
    }
}

fn fold_completed_trial(
    root: &Path,
    trial: &BatchTrialReport,
    observations: &BTreeMap<String, Vec<Finding>>,
    policy: IdentityFoldPolicy,
    context: &OccurrenceFoldContext,
    groups: &mut BTreeMap<String, OccurrenceAccumulator>,
) -> Result<()> {
    let current = trial
        .run_id
        .as_ref()
        .context("completed batch trial has no current run")?;
    let runs = super::load::observation_run_refs(root, std::slice::from_ref(current))?;
    let mut keys = BTreeSet::new();
    for run in runs {
        for finding in observations
            .get(&run)
            .context("completed run is outside retained observations")?
        {
            keys.insert(context.projection_key(finding, policy));
        }
    }
    for key in keys {
        groups
            .get_mut(&key)
            .context("completed observation has no retained group")?
            .seen += 1;
    }
    Ok(())
}

#[derive(Default)]
struct OccurrenceFoldContext {
    strong_fingerprints: BTreeSet<(String, String)>,
}

impl OccurrenceFoldContext {
    fn load(observations: &BTreeMap<String, Vec<Finding>>) -> Self {
        let mut context = Self::default();
        for finding in observations.values().flatten() {
            context.observe(finding);
        }
        context
    }

    fn observe(&mut self, finding: &Finding) {
        let Some(identity_id) = finding.identity_id.as_ref() else {
            return;
        };
        if finding.effective_identity_basis().is_strong() {
            self.strong_fingerprints
                .insert((identity_id.clone(), finding.fingerprint.clone()));
        }
    }

    fn projection_key(&self, finding: &Finding, policy: IdentityFoldPolicy) -> String {
        if policy == IdentityFoldPolicy::Safe {
            if let Some(identity_id) = self.strong_fingerprint_identity(finding) {
                return format!("identity:{identity_id}");
            }
        }
        finding_projection_key(finding, policy)
    }

    /// Returns the identity the fold key is built from, so a finding without
    /// one can never reach the `identity:` branch. Answering `bool` here and
    /// re-reading `identity_id` at the call site allowed an absent identity to
    /// fold every such finding into one empty `identity:` bucket.
    fn strong_fingerprint_identity<'a>(&self, finding: &'a Finding) -> Option<&'a str> {
        let identity_id = finding.identity_id.as_ref()?;
        self.strong_fingerprints
            .contains(&(identity_id.clone(), finding.fingerprint.clone()))
            .then_some(identity_id.as_str())
    }
}

#[derive(Default)]
struct OccurrenceAccumulator {
    seen: usize,
    identities: BTreeSet<String>,
    bases: BTreeSet<FindingIdentityBasis>,
    severities: BTreeSet<String>,
    locations: BTreeSet<String>,
    titles: BTreeSet<String>,
    fingerprints: BTreeSet<String>,
    run_ids: BTreeSet<String>,
    representative: Option<Finding>,
}

impl OccurrenceAccumulator {
    fn observe_finding(&mut self, run: &str, finding: &Finding) {
        self.run_ids.insert(run.to_string());
        self.observe_variants(finding);
        if self
            .representative
            .as_ref()
            .is_none_or(|current| evidence_rank(finding) > evidence_rank(current))
        {
            self.representative = Some(finding.clone());
        }
    }

    fn observe_variants(&mut self, finding: &Finding) {
        if let Some(identity_id) = finding.identity_id.as_ref() {
            self.identities.insert(identity_id.clone());
            self.bases.insert(finding.effective_identity_basis());
        }
        self.severities
            .insert(finding.severity.as_str().to_string());
        self.locations.insert(finding_location(finding));
        self.titles.insert(finding.title.clone());
        self.fingerprints.insert(finding.fingerprint.clone());
    }

    fn finish(self, fold_key: String, counts: LogicalTrialCounts) -> BatchOccurrenceRow {
        let representative = self.representative.expect("observed groups are non-empty");
        BatchOccurrenceRow {
            fold_key,
            identity_id: only_value(self.identities),
            identity_basis: only_value(self.bases),
            seen: self.seen,
            completed: counts.completed,
            planned: counts.planned,
            failed: counts.failed,
            severities: self.severities.into_iter().collect(),
            locations: self.locations.into_iter().collect(),
            titles: self.titles.into_iter().collect(),
            fingerprints: self.fingerprints.into_iter().collect(),
            run_ids: self.run_ids.into_iter().collect(),
            representative_observation_ref: representative
                .id
                .filter(|id| *id > 0)
                .map(|id| format!("generation:{id}")),
            representative_fingerprint: representative.fingerprint.clone(),
            representative_title: representative.title.clone(),
            representative_severity: representative.severity.as_str().to_string(),
            representative_location: finding_location(&representative),
        }
    }
}

fn only_value<T: Ord>(values: BTreeSet<T>) -> Option<T> {
    (values.len() == 1)
        .then(|| values.into_iter().next())
        .flatten()
}

fn evidence_rank(finding: &Finding) -> (u8, u8, usize, Severity) {
    let verification = u8::from(finding.verification.is_some());
    let proof = finding.static_proof_state.map(proof_rank).unwrap_or(0);
    (
        verification,
        proof,
        finding.evidence.len(),
        finding.severity,
    )
}

fn proof_rank(state: StaticProofState) -> u8 {
    match state {
        StaticProofState::StaticallyConfirmed | StaticProofState::StaticallyRejected => 6,
        StaticProofState::SanitizerChecked => 5,
        StaticProofState::SourceSinkLinked => 4,
        StaticProofState::CodeCited => 3,
        StaticProofState::NeedsRuntimeEvidence => 2,
        StaticProofState::SignalOnly => 1,
    }
}

fn finding_location(finding: &Finding) -> String {
    format!("{}:{}", finding.file_path, finding.start_line)
}

#[cfg(test)]
mod tests;
