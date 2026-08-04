use crate::support::require_cli_target;
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
    let target = require_cli_target("findings", target, None)?;
    let workspace = WorkspaceTarget::new(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let report = store.list_findings_filtered(&filter)?;

    if json {
        // The aliased rows, not the raw report: aliases are how decisions
        // and detail lookups address findings, so the machine output must
        // carry the same ledger-stable aliases the plain table shows.
        println!(
            "{}",
            serde_json::to_string_pretty(&report.aliased_rows_json())?
        );
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
    let target = require_cli_target("finding", target, None)?;
    let workspace = WorkspaceTarget::new(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    // Aliases are positional over the sorted WHOLE ledger; resolving against
    // a clamped list both loses aliases past the limit and can assign the
    // same alias to a different finding than exports/lists over the full set.
    let all_findings = store.list_all_findings()?;

    // Keep the alias-resolved row itself: fingerprints can collide across
    // sibling findings (they exclude the line), so a fingerprint round-trip
    // could silently swap in a different finding than the alias names.
    let finding = if let Some(alias_finding) = resolve_finding_alias(&all_findings, &reference) {
        alias_finding
    } else {
        store
            .get_finding_by_reference(&reference)?
            .with_context(|| missing_finding_message(&reference, &workspace))?
    };
    let alias = stable_finding_alias(&all_findings, &finding.fingerprint);
    let patch_results = store.get_patch_results_for_finding(&finding.fingerprint)?;
    let decisions = finding
        .id
        .map(|finding_id| store.list_review_decisions_for_finding_identity(finding_id))
        .transpose()?
        .unwrap_or_default();
    let report =
        FindingDetailReport::new(alias, finding, patch_results).with_review_decisions(decisions);

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
    let all_findings = store.list_all_findings()?;
    if let Some(alias_finding) = resolve_finding_alias(&all_findings, reference) {
        // No fingerprint round-trip: colliding fingerprints would swap in a
        // sibling finding at a different line than the alias names.
        return Ok(alias_finding);
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
