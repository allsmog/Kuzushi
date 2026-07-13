use super::*;
use anyhow::Result;
use kuzushi_core::{sorted_finding_alias_indices, FindingStore};
use std::path::Path;

pub(crate) fn open_finding_store_for_target_read_only(
    target: Option<&PathBuf>,
) -> Result<(WorkspaceTarget, FindingStore)> {
    let workspace = workspace_for_target(target)?;
    let path = workspace.findings_db_path();
    let store = if path.exists() {
        FindingStore::open_read_only(path)?
    } else {
        FindingStore::open(path)?
    };
    Ok((workspace, store))
}

pub(crate) fn finding_by_reference_for_target(
    target: Option<&PathBuf>,
    reference: &str,
) -> Result<Option<Finding>> {
    let (_, store) = open_finding_store_for_target_read_only(target)?;
    store.get_finding_by_reference(reference)
}

pub(crate) fn load_finding_completion_values(target: &Path) -> Vec<String> {
    finding_completion_values(
        load_findings_for_target(Some(&target.to_path_buf()), 200).unwrap_or_default(),
    )
}

pub(crate) fn finding_completion_values_from_findings(findings: &[Finding]) -> Vec<String> {
    finding_completion_values(findings.to_vec())
}

fn load_findings_for_target(target: Option<&PathBuf>, limit: usize) -> Result<Vec<Finding>> {
    let (_, store) = open_finding_store_for_target_read_only(target)?;
    store.list_findings(limit)
}

fn finding_completion_values(findings: Vec<Finding>) -> Vec<String> {
    let mut values = Vec::new();
    for (alias, index) in sorted_finding_alias_indices(&findings) {
        let Some(finding) = findings.get(index) else {
            continue;
        };
        values.push(alias);
        values.push(short_fingerprint(&finding.fingerprint));
        values.push(finding.fingerprint.clone());
    }
    values
}
