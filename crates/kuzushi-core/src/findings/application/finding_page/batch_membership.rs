use super::*;
use crate::findings::derive_batch_occurrence_report_for_controller;
use std::collections::BTreeSet;

pub(super) struct BatchPageMembership {
    pub(super) signature: Vec<u8>,
    pub(super) report: crate::findings::BatchOccurrenceReport,
    fingerprints: BTreeSet<String>,
}

impl BatchPageMembership {
    pub(super) fn load(
        store: &FindingStore,
        workspace: &WorkspaceTarget,
        batch: Option<&str>,
        policy: IdentityFoldPolicy,
    ) -> Result<Option<Self>> {
        let Some(id) = batch else {
            return Ok(None);
        };
        crate::capabilities::campaign::validate_scan_batch_id(id)?;
        let report = derive_batch_occurrence_report_for_controller(workspace.root(), id, store)?;
        let fingerprints =
            report.retained_representative_fingerprints(workspace.root(), store, policy)?;
        Ok(Some(Self {
            signature: serde_json::to_vec(&report)?,
            report,
            fingerprints,
        }))
    }

    fn contains(&self, finding: &Finding) -> bool {
        self.fingerprints.contains(&finding.fingerprint)
    }
}

pub(super) fn matching_report(
    store: &FindingStore,
    filter: &FindingListFilter,
    policy: IdentityFoldPolicy,
    membership: Option<&BatchPageMembership>,
) -> Result<FindingListReport> {
    let mut ledger_filter = filter.clone();
    ledger_filter.batch_id = None;
    ledger_filter.scope_id.clear();
    ledger_filter.scope_record.clear();
    if filter.has_scope_filter() {
        ledger_filter.run_id.clear();
    }
    let mut report = store.matching_findings_for_page(&ledger_filter, policy)?;
    let Some(membership) = membership else {
        return Ok(report);
    };
    let (findings, aliases) = report
        .findings
        .into_iter()
        .zip(report.aliases)
        .filter(|(finding, _)| membership.contains(finding))
        .unzip();
    report.findings = findings;
    report.aliases = aliases;
    report.count = report.findings.len();
    let selected = report
        .findings
        .iter()
        .map(|finding| finding.fingerprint.as_str())
        .collect::<BTreeSet<_>>();
    report
        .review_decisions
        .retain(|fingerprint, _| selected.contains(fingerprint.as_str()));
    Ok(report)
}
