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

pub(crate) fn findings_batch_command(
    target: Option<PathBuf>,
    batch_id: String,
    json: bool,
) -> Result<()> {
    let target = require_cli_target("findings batch", target, None)?;
    let workspace = WorkspaceTarget::new(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let report = kuzushi_core::findings::derive_batch_occurrence_report(
        workspace.root(),
        &batch_id,
        &store,
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", report.output());
    }
    Ok(())
}

pub(crate) fn findings_identity_audit_command(target: Option<PathBuf>, json: bool) -> Result<()> {
    let target = require_cli_target("findings identity-audit", target, None)?;
    let workspace = WorkspaceTarget::new(target)?;
    let evidence =
        kuzushi_core::findings::current_finding_identity_audit_evidence(workspace.root())?;
    if json {
        println!("{}", serde_json::to_string_pretty(&evidence)?);
    } else {
        println!("{}", identity_audit_output(&evidence));
    }
    Ok(())
}

pub(crate) fn findings_identity_audit_approve_command(
    target: Option<PathBuf>,
    input: PathBuf,
    json: bool,
) -> Result<()> {
    let target = require_cli_target("findings identity-audit approve", target, None)?;
    let paths = kuzushi_core::ConfigPaths::from_target(Some(&target))?;
    let receipt = approve_identity_audit_from_path(&paths.global_state_dir(), &target, &input)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&receipt)?);
    } else {
        let path = kuzushi_core::findings::identity_audit_approval_receipt_path(
            &paths.global_state_dir(),
            &receipt.canonical_target_key,
        );
        println!(
            "identity audit approved · {} groups · {}\nreceipt: {}",
            receipt.dispositions.len(),
            receipt.report_sha256,
            path.display()
        );
    }
    Ok(())
}

fn approve_identity_audit_from_path(
    operator_state_dir: &std::path::Path,
    target: &std::path::Path,
    input: &std::path::Path,
) -> Result<kuzushi_core::findings::FindingIdentityAuditApprovalReceipt> {
    let bytes = read_bounded_approval(input)?;
    let request = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "{} is not a valid identity-audit approval request",
            input.display()
        )
    })?;
    kuzushi_core::findings::approve_finding_identity_audit(operator_state_dir, target, request)
}

fn read_bounded_approval(path: &std::path::Path) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "could not inspect identity-audit approval {}",
            path.display()
        )
    })?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "identity-audit approval must be a regular file"
    );
    anyhow::ensure!(
        metadata.len() <= 1024 * 1024,
        "identity-audit approval exceeds 1 MiB"
    );
    std::fs::read(path)
        .with_context(|| format!("could not read identity-audit approval {}", path.display()))
}

fn identity_audit_output(
    evidence: &kuzushi_core::findings::FindingIdentityAuditEvidence,
) -> String {
    let report = &evidence.report;
    let mut lines = vec![format!(
        "identity audit · {} findings · {} identity groups · {} suspicious",
        report.findings_scanned,
        report.identity_groups_scanned,
        report.suspicious_groups.len()
    )];
    lines.extend(report.suspicious_groups.iter().map(|group| {
        let issues = group
            .issues
            .iter()
            .map(identity_audit_issue_label)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{} · finding ids {} · {}",
            group.identity_id,
            group
                .finding_ids
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(","),
            issues
        )
    }));
    lines.push(format!("report: {}", evidence.report_sha256));
    lines.push(format!("corpus: {}", evidence.corpus_watermark));
    if !report.suspicious_groups.is_empty() {
        lines.push(
            "Next: author a disposition and rationale for every group, then run `kuzushi findings identity-audit approve --from <approval.json>`"
                .to_string(),
        );
    }
    lines.join("\n")
}

fn identity_audit_issue_label(
    issue: &kuzushi_core::findings::FindingIdentityAuditIssueKind,
) -> String {
    serde_json::to_value(issue)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
        .replace('_', "-")
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

#[cfg(test)]
mod identity_audit_approval_tests {
    use super::*;
    use kuzushi_core::findings::{
        identity_audit_approval_receipt_path, IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION,
    };

    #[test]
    fn approval_application_reads_request_and_writes_only_operator_state() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let operator_state = temp.path().join("operator/.kuzushi/v3");
        std::fs::create_dir_all(&target).unwrap();
        let workspace = WorkspaceTarget::new(&target).unwrap();
        workspace.ensure_state_dir().unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        let evidence =
            kuzushi_core::findings::current_finding_identity_audit_evidence(&target).unwrap();
        let request_path = temp.path().join("approval.json");
        std::fs::write(
            &request_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "schemaVersion": IDENTITY_AUDIT_APPROVAL_SCHEMA_VERSION,
                "canonicalTargetKey": evidence.canonical_target_key,
                "corpusWatermark": evidence.corpus_watermark,
                "reportSha256": evidence.report_sha256,
                "actor": "security-owner",
                "dispositions": []
            }))
            .unwrap(),
        )
        .unwrap();

        let receipt =
            approve_identity_audit_from_path(&operator_state, &target, &request_path).unwrap();

        let receipt_path =
            identity_audit_approval_receipt_path(&operator_state, &receipt.canonical_target_key);
        assert!(receipt_path.is_file());
        assert!(!target.join(".kuzushi/v3/identity-audit-approvals").exists());
    }

    #[test]
    fn approval_application_rejects_unknown_request_fields() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let operator_state = temp.path().join("operator/.kuzushi/v3");
        std::fs::create_dir_all(&target).unwrap();
        let workspace = WorkspaceTarget::new(&target).unwrap();
        workspace.ensure_state_dir().unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        let request_path = temp.path().join("approval.json");
        std::fs::write(
            &request_path,
            br#"{"schemaVersion":1,"canonicalTargetKey":"target","corpusWatermark":"sha256:00","reportSha256":"sha256:00","actor":"owner","dispositions":[],"approved":true}"#,
        )
        .unwrap();

        let error = approve_identity_audit_from_path(&operator_state, &target, &request_path)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("not a valid identity-audit approval request"),
            "{error}"
        );
    }
}
