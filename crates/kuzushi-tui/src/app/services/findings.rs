use super::*;
use anyhow::Result;
use kuzushi_core::{sorted_finding_aliases, FindingStore};

pub(crate) fn open_finding_store_for_target(
    target: Option<&PathBuf>,
) -> Result<(WorkspaceTarget, FindingStore)> {
    let workspace = workspace_for_target(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    Ok((workspace, store))
}

pub(crate) fn finding_by_reference_for_target(
    target: Option<&PathBuf>,
    reference: &str,
) -> Result<Option<Finding>> {
    let (_, store) = open_finding_store_for_target(target)?;
    store.get_finding_by_reference(reference)
}

pub(crate) fn finding_completion_values_for_target(
    target: Option<&PathBuf>,
    cached_findings: &[Finding],
) -> Vec<String> {
    finding_completion_values(completion_findings(target, cached_findings))
}

fn completion_findings(target: Option<&PathBuf>, cached_findings: &[Finding]) -> Vec<Finding> {
    if !cached_findings.is_empty() {
        return cached_findings.to_vec();
    }
    load_findings_for_target(target, 200).unwrap_or_default()
}

fn load_findings_for_target(target: Option<&PathBuf>, limit: usize) -> Result<Vec<Finding>> {
    let (_, store) = open_finding_store_for_target(target)?;
    store.list_findings(limit)
}

fn finding_completion_values(findings: Vec<Finding>) -> Vec<String> {
    let mut values = Vec::new();
    for (alias, finding) in sorted_finding_aliases(&findings) {
        values.push(alias);
        values.push(short_fingerprint(&finding.fingerprint));
        values.push(finding.fingerprint);
    }
    values
}
