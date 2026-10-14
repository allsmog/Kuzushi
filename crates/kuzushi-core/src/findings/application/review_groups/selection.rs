use super::*;
use crate::findings::{FindingListFilter, FindingStore, IdentityFoldPolicy};
use crate::WorkspaceTarget;
use std::collections::BTreeSet;

pub(super) struct Selection {
    pub findings: Vec<Finding>,
    pub aliases: Vec<String>,
    pub run_refs: BTreeSet<String>,
}

pub(super) fn load(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    request: &FindingGroupsRequest,
) -> Result<Selection> {
    let filter = request
        .filter
        .as_deref()
        .map(FindingListFilter::from_filter_expression)
        .transpose()?
        .unwrap_or_default();
    let report = super::super::finding_page::matching_report_with_provenance(
        store,
        workspace,
        &filter,
        IdentityFoldPolicy::Safe,
    )?;
    let run_refs = crate::run_artifacts::scan_finding_run_refs(workspace.root(), &request.run_ids)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let (findings, aliases) = report
        .findings
        .into_iter()
        .zip(report.aliases)
        .filter(|(finding, _)| run_refs.is_empty() || !matching_runs(finding, &run_refs).is_empty())
        .unzip();
    Ok(Selection {
        findings,
        aliases,
        run_refs,
    })
}

pub(super) fn matching_runs(finding: &Finding, run_refs: &BTreeSet<String>) -> Vec<String> {
    finding
        .scan_id
        .iter()
        .chain(
            finding
                .sources
                .iter()
                .flat_map(|source| [&source.first_scan_id, &source.last_scan_id]),
        )
        .filter(|run| run_refs.contains(*run))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
