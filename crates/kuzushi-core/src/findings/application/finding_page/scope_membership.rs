//! Historical accepted membership comes from authenticated requests, never paths.
use super::*;
use crate::run_artifacts::{load_run_request_scope, RecordedRequestScope};
use crate::workspace::ScanScopeRef;
use std::collections::BTreeSet;

const MAX_SCOPE_RUNS: usize = 4096;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingScopeFilterReceipt {
    pub observed_runs: usize,
    pub matched_runs: usize,
    pub matched_run_ids: Vec<String>,
    pub unbound_runs: usize,
    pub unavailable_runs: Vec<String>,
    pub references: Vec<ScanScopeRef>,
}

pub(super) struct ScopePageMembership {
    pub(super) receipt: FindingScopeFilterReceipt,
    fingerprints: BTreeSet<String>,
}

impl ScopePageMembership {
    pub(super) fn load(
        store: &FindingStore,
        workspace: &WorkspaceTarget,
        filter: &FindingListFilter,
        policy: IdentityFoldPolicy,
        batch: Option<&BatchPageMembership>,
    ) -> Result<Option<Self>> {
        if !filter.has_scope_filter() {
            return Ok(None);
        }
        let allowed = batch
            .map(|batch| batch.report.retained_observation_run_ids(workspace.root()))
            .transpose()?;
        let runs = store.observed_run_ids(MAX_SCOPE_RUNS, &filter.run_id, allowed.as_deref())?;
        let mut selected = ScopeRunSelection::default();
        for run in &runs {
            selected.observe(workspace, run, filter);
        }
        selected.receipt.observed_runs = runs.len();
        let fingerprints = store.finding_fingerprints_observed_in_runs(&selected.runs, policy)?;
        selected.receipt.matched_run_ids = selected.runs;
        Ok(Some(Self {
            receipt: selected.receipt,
            fingerprints,
        }))
    }

    pub(super) fn apply(&self, report: &mut FindingListReport) {
        let (findings, aliases) = std::mem::take(&mut report.findings)
            .into_iter()
            .zip(std::mem::take(&mut report.aliases))
            .filter(|(finding, _)| self.fingerprints.contains(&finding.fingerprint))
            .unzip();
        report.findings = findings;
        report.aliases = aliases;
        report.count = report.findings.len();
        report
            .review_decisions
            .retain(|id, _| self.fingerprints.contains(id));
    }
}

#[derive(Default)]
struct ScopeRunSelection {
    receipt: FindingScopeFilterReceipt,
    runs: Vec<String>,
}

impl ScopeRunSelection {
    fn observe(&mut self, workspace: &WorkspaceTarget, run: &str, filter: &FindingListFilter) {
        match load_run_request_scope(workspace.root(), run) {
            Ok(RecordedRequestScope::Accepted { reference, .. }) => {
                self.observe_reference(workspace, run, reference, filter)
            }
            Ok(_) => self.receipt.unbound_runs += 1,
            Err(_) => self.receipt.unavailable_runs.push(run.into()),
        }
    }

    fn observe_reference(
        &mut self,
        workspace: &WorkspaceTarget,
        run: &str,
        reference: ScanScopeRef,
        filter: &FindingListFilter,
    ) {
        if !matches_reference(filter, &reference) || !matches_run_id(filter, run) {
            return;
        }
        match matches_source(workspace, filter, run) {
            Ok(true) => self.retain(run, reference),
            Ok(false) => {}
            Err(_) => self.receipt.unavailable_runs.push(run.into()),
        }
    }

    fn retain(&mut self, run: &str, reference: ScanScopeRef) {
        self.runs.push(run.into());
        self.receipt.matched_runs += 1;
        if !self.receipt.references.contains(&reference) {
            self.receipt.references.push(reference);
        }
    }
}

fn matches_source(
    workspace: &WorkspaceTarget,
    filter: &FindingListFilter,
    run: &str,
) -> Result<bool> {
    if !filter.has_provenance_filter() {
        return Ok(true);
    }
    let summary = crate::run_artifacts::load_run_summary_without_repair(workspace.root(), run)?;
    anyhow::ensure!(
        summary.target_git.is_some(),
        "Recorded source identity is unavailable"
    );
    Ok(filter.matches_summary_provenance(&summary))
}

fn matches_reference(filter: &FindingListFilter, reference: &ScanScopeRef) -> bool {
    (filter.scope_id.is_empty() || filter.scope_id.contains(&reference.scope_id))
        && (filter.scope_record.is_empty()
            || filter
                .scope_record
                .contains(&reference.proposal.record_hash))
}

fn matches_run_id(filter: &FindingListFilter, run: &str) -> bool {
    filter.run_id.is_empty()
        || filter
            .run_id
            .iter()
            .any(|id| run.to_ascii_lowercase().starts_with(id))
}

#[cfg(test)]
mod tests;
