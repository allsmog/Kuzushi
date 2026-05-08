use anyhow::{Context, Result};
use kuzushi_core::{
    resolve_finding_alias, stable_finding_alias, FindingDetailReport, FindingListFilter,
    FindingStore, WorkspaceTarget,
};
use std::path::PathBuf;

pub(crate) fn findings_command(
    target: Option<PathBuf>,
    filter: FindingListFilter,
    json: bool,
) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let report = store.list_findings_filtered(&filter)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if report.findings.is_empty() {
        println!(
            "no findings found at {}\nNext: kuzushi scan {}",
            workspace.findings_db_path().display(),
            workspace.root().display()
        );
    } else {
        println!("{}", report.output());
    }
    Ok(())
}

pub(crate) fn finding_command(
    target: Option<PathBuf>,
    reference: String,
    json: bool,
) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let all_findings = store
        .list_findings_filtered(&FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT))?
        .findings;

    let finding = if let Some(alias_finding) = resolve_finding_alias(&all_findings, &reference) {
        store
            .get_finding_by_fingerprint(&alias_finding.fingerprint)?
            .unwrap_or(alias_finding)
    } else {
        store
            .get_finding_by_reference(&reference)?
            .with_context(|| missing_finding_message(&reference, &workspace))?
    };
    let alias = stable_finding_alias(&all_findings, &finding.fingerprint);
    let patch_results = store.get_patch_results_for_finding(&finding.fingerprint)?;
    let report = FindingDetailReport::new(alias, finding, patch_results);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", report.output());
    }
    Ok(())
}

pub(crate) fn resolve_persisted_finding(
    store: &FindingStore,
    reference: &str,
    workspace: &WorkspaceTarget,
) -> Result<kuzushi_core::Finding> {
    let all_findings = store
        .list_findings_filtered(&FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT))?
        .findings;
    if let Some(alias_finding) = resolve_finding_alias(&all_findings, reference) {
        return Ok(store
            .get_finding_by_fingerprint(&alias_finding.fingerprint)?
            .unwrap_or(alias_finding));
    }
    store
        .get_finding_by_reference(reference)?
        .with_context(|| missing_finding_message(reference, workspace))
}

fn missing_finding_message(reference: &str, workspace: &WorkspaceTarget) -> String {
    format!(
        "no finding found for {reference:?} at {}\nNext: kuzushi findings --target {}",
        workspace.findings_db_path().display(),
        workspace.root().display()
    )
}
